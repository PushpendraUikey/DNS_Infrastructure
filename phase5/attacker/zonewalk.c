/*
 * NSEC zone-walker.
 *
 * A signed zone proves a name does NOT exist with an NSEC record whose "next
 * domain name" field points at the next name that DOES exist, in canonical
 * order. Walking that chain reveals every name in the zone - including ones
 * that are never advertised.
 *
 * This asks the authoritative server (domain-ns) for each name's NSEC record,
 * reads the next name out of it, and repeats until the chain wraps back to the
 * apex. Queries are built and sent with libpcap (pcap_inject) and the replies
 * captured with libpcap - no sockets, no dnspython/scapy.
 *
 * It sits on the resolver subnet (172.16.2.100) and reaches the authoritative
 * subnet through the core-router, so every query frame is addressed at layer 2
 * to the router and at layer 3 to domain-ns.
 *
 * Build:  gcc -O2 -Wall -o zonewalk zonewalk.c -lpcap
 * Run:    ./zonewalk example.com eth0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>

#define ETH_HLEN 14
#define T_NSEC   47

static const char *DOMAIN_NS = "172.16.3.30";   /* authoritative for example.com */
static const char *GATEWAY   = "172.16.2.3";    /* core-router: next hop to the auth subnet */
static const char *MY_IP     = "172.16.2.100";  /* this host */

/* ---- checksums ---- */
static void fix_ip_checksum(uint8_t *iph, int ihl) {
    iph[10] = iph[11] = 0;
    uint32_t s = 0;
    for (int i = 0; i + 1 < ihl; i += 2) s += (iph[i] << 8) | iph[i + 1];
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    uint16_t c = ~s; iph[10] = c >> 8; iph[11] = c & 0xff;
}
static uint16_t udp_checksum(const uint8_t *src, const uint8_t *dst,
                             const uint8_t *udp, int len) {
    uint32_t s = 0;
    s += (src[0]<<8)|src[1]; s += (src[2]<<8)|src[3];
    s += (dst[0]<<8)|dst[1]; s += (dst[2]<<8)|dst[3];
    s += 17; s += len;
    for (int i = 0; i + 1 < len; i += 2) s += (udp[i]<<8)|udp[i+1];
    if (len & 1) s += udp[len-1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    uint16_t c = ~s; return c ? c : 0xffff;
}

/* ---- names ---- */
static int str_to_wire(const char *s, uint8_t *w) {
    int o = 0; const char *p = s;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        if (len <= 0 || len > 63) return -1;
        w[o++] = len; memcpy(w + o, p, len); o += len;
        p += len; if (*p == '.') p++;
    }
    w[o++] = 0; return o;
}
static void wire_to_str(const uint8_t *w, char *out) {
    int o = 0, i = 0;
    if (w[0] == 0) { out[0] = '.'; out[1] = 0; return; }
    while (w[i]) { int len = w[i++]; for (int j = 0; j < len; j++) out[o++] = w[i++]; out[o++] = '.'; }
    if (o) o--; out[o] = 0;
}
static int wire_eq(const uint8_t *a, const uint8_t *b) {
    int i = 0;
    for (;;) {
        uint8_t la = a[i], lb = b[i];
        if (la != lb) return 0;
        if (la == 0) return 1;
        for (int j = 1; j <= la; j++) {
            char x = a[i+j], y = b[i+j];
            if (x>='A'&&x<='Z') x+=32; if (y>='A'&&y<='Z') y+=32;
            if (x != y) return 0;
        }
        i += la + 1;
    }
}
/* expand a (possibly compressed) name; returns bytes consumed at pos, sets *outlen */
static int read_name(const uint8_t *m, int ml, int pos, uint8_t *out, int *outlen) {
    int op = 0, jumped = 0, adv = -1, guard = 0, p = pos;
    while (p >= 0 && p < ml) {
        uint8_t c = m[p];
        if ((c & 0xc0) == 0xc0) { if (p+1>=ml) return -1; if (!jumped) adv=(p+2)-pos;
            jumped = 1; p = ((c&0x3f)<<8)|m[p+1]; if (++guard>128) return -1; continue; }
        if (c > 63) return -1;
        if (c == 0) { out[op++]=0; if (!jumped) adv=(p+1)-pos; *outlen=op; return adv; }
        if (p+1+c>ml || op+1+c>255) return -1;
        out[op++]=c; memcpy(out+op, m+p+1, c); op+=c; p+=1+c;
    }
    return -1;
}

/* ---- link layer ---- */
static int get_if_mac(const char *ifn, uint8_t *out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd < 0) return -1;
    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifn, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return -1; }
    memcpy(out, ifr.ifr_hwaddr.sa_data, 6); close(fd); return 0;
}
static int arp_resolve(pcap_t *h, const uint8_t *mymac, const char *myip,
                       const char *target, uint8_t *out) {
    uint8_t spa[4], tpa[4];
    inet_pton(AF_INET, myip, spa); inet_pton(AF_INET, target, tpa);
    uint8_t q[42]; memset(q, 0, sizeof(q));
    memset(q, 0xff, 6); memcpy(q+6, mymac, 6); q[12]=0x08; q[13]=0x06;
    q[14]=0; q[15]=1; q[16]=8; q[17]=0; q[18]=6; q[19]=4; q[20]=0; q[21]=1;
    memcpy(q+22, mymac, 6); memcpy(q+28, spa, 4); memcpy(q+38, tpa, 4);
    struct bpf_program fp;
    if (pcap_compile(h, &fp, "arp", 1, PCAP_NETMASK_UNKNOWN)==0){ pcap_setfilter(h,&fp); pcap_freecode(&fp);}
    for (int t = 0; t < 40; t++) {
        pcap_inject(h, q, sizeof(q));
        for (int k = 0; k < 50; k++) {
            struct pcap_pkthdr *hd; const uint8_t *d;
            int r = pcap_next_ex(h, &hd, &d);
            if (r == 0) break;
            if (r != 1 || hd->caplen < 42) continue;
            if (d[12]==0x08 && d[13]==0x06 && ((d[20]<<8)|d[21])==2 && !memcmp(d+28, tpa, 4)) {
                memcpy(out, d+22, 6); return 0;
            }
        }
    }
    return -1;
}

/* Build a full DNS query frame for qname/qtype with EDNS(DO). Returns length. */
static int build_query(uint8_t *f, const uint8_t *dmac, const uint8_t *smac,
                       const uint8_t *qname, int qnl, uint16_t qtype, uint16_t txid) {
    /* DNS payload */
    uint8_t dns[512]; int d = 0;
    dns[d++]=txid>>8; dns[d++]=txid&0xff;
    dns[d++]=0x00; dns[d++]=0x00;          /* flags: standard query, RD=0 */
    dns[d++]=0x00; dns[d++]=0x01;          /* qdcount */
    dns[d++]=0x00; dns[d++]=0x00;          /* ancount */
    dns[d++]=0x00; dns[d++]=0x00;          /* nscount */
    dns[d++]=0x00; dns[d++]=0x01;          /* arcount: OPT */
    memcpy(dns+d, qname, qnl); d += qnl;   /* qname */
    dns[d++]=qtype>>8; dns[d++]=qtype&0xff;/* qtype */
    dns[d++]=0x00; dns[d++]=0x01;          /* qclass IN */
    /* OPT record: root name, type 41, class 4096, ttl DO=1, rdlen 0 */
    dns[d++]=0x00;
    dns[d++]=0x00; dns[d++]=0x29;
    dns[d++]=0x10; dns[d++]=0x00;
    dns[d++]=0x00; dns[d++]=0x00; dns[d++]=0x80; dns[d++]=0x00;
    dns[d++]=0x00; dns[d++]=0x00;

    uint8_t sip[4], dip[4];
    inet_pton(AF_INET, MY_IP, sip); inet_pton(AF_INET, DOMAIN_NS, dip);
    int o = 0;
    memcpy(f+o, dmac, 6); o+=6; memcpy(f+o, smac, 6); o+=6;
    f[o++]=0x08; f[o++]=0x00;                       /* IPv4 */
    uint8_t *ip = f + o;
    int iptot = 20 + 8 + d;
    ip[0]=0x45; ip[1]=0; ip[2]=iptot>>8; ip[3]=iptot&0xff;
    ip[4]=0; ip[5]=0; ip[6]=0x40; ip[7]=0;          /* DF */
    ip[8]=64; ip[9]=17; ip[10]=0; ip[11]=0;
    memcpy(ip+12, sip, 4); memcpy(ip+16, dip, 4);
    fix_ip_checksum(ip, 20);
    uint8_t *udp = ip + 20;
    uint16_t sport = 20000 + (txid & 0x3fff);
    udp[0]=sport>>8; udp[1]=sport&0xff; udp[2]=0; udp[3]=53;
    int ulen = 8 + d; udp[4]=ulen>>8; udp[5]=ulen&0xff; udp[6]=0; udp[7]=0;
    memcpy(udp+8, dns, d);
    uint16_t c = udp_checksum(ip+12, ip+16, udp, ulen); udp[6]=c>>8; udp[7]=c&0xff;
    return ETH_HLEN + iptot;
}

/* Find an NSEC record anywhere in the message, read its next-name. 1 if found. */
static int find_nsec_next(const uint8_t *dns, int dnslen, uint8_t *out, int *outlen) {
    if (dnslen < 12) return 0;
    int qd=(dns[4]<<8)|dns[5];
    int total=((dns[6]<<8)|dns[7])+((dns[8]<<8)|dns[9])+((dns[10]<<8)|dns[11]);
    int p = 12, nl; uint8_t nb[256];
    for (int q = 0; q < qd; q++) { int a=read_name(dns,dnslen,p,nb,&nl); if(a<0)return 0; p+=a+4; }
    for (int r = 0; r < total; r++) {
        int a = read_name(dns, dnslen, p, nb, &nl); if (a < 0) return 0;
        int rr = p + a; if (rr + 10 > dnslen) return 0;
        uint16_t type=(dns[rr]<<8)|dns[rr+1];
        uint16_t rdlen=(dns[rr+8]<<8)|dns[rr+9];
        int rdata = rr + 10; if (rdata + rdlen > dnslen) return 0;
        if (type == T_NSEC) { if (read_name(dns, dnslen, rdata, out, outlen) < 0) return 0; return 1; }
        p = rdata + rdlen;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *apex   = argc > 1 ? argv[1] : "example.com";
    const char *ifname = argc > 2 ? argv[2] : "eth0";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *h = pcap_open_live(ifname, 65535, 1, 300, errbuf);
    if (!h) { fprintf(stderr, "pcap: %s\n", errbuf); return 1; }
    pcap_setdirection(h, PCAP_D_IN);

    uint8_t mymac[6], gwmac[6];
    if (get_if_mac(ifname, mymac)) { fprintf(stderr, "no mac\n"); return 1; }
    if (arp_resolve(h, mymac, MY_IP, GATEWAY, gwmac)) {
        fprintf(stderr, "cannot ARP gateway %s\n", GATEWAY); return 1; }

    char filter[128];
    snprintf(filter, sizeof(filter), "udp and src port 53 and ip src host %s", DOMAIN_NS);
    struct bpf_program fp;
    if (pcap_compile(h, &fp, filter, 1, PCAP_NETMASK_UNKNOWN)) { fprintf(stderr,"filter\n"); return 1; }
    pcap_setfilter(h, &fp); pcap_freecode(&fp);

    srand(time(NULL) ^ getpid());
    uint8_t cur[256], next[256]; int curl, nextl;
    curl = str_to_wire(apex, cur);
    uint8_t apexw[256]; str_to_wire(apex, apexw);

    char recovered[64][256]; int nrec = 0, queries = 0;
    printf("[zonewalk] walking %s via NSEC at %s (through %s)\n", apex, DOMAIN_NS, GATEWAY);

    for (int step = 0; step < 64; step++) {
        uint16_t txid = rand() & 0xffff;
        uint8_t frame[1500];
        int flen = build_query(frame, gwmac, mymac, cur, curl, T_NSEC, txid);

        int got = 0;
        for (int attempt = 0; attempt < 5 && !got; attempt++) {
            pcap_inject(h, frame, flen);
            for (int k = 0; k < 200; k++) {
                struct pcap_pkthdr *hd; const uint8_t *d;
                int r = pcap_next_ex(h, &hd, &d);
                if (r == 0) break;
                if (r != 1) continue;
                int ihl = (d[ETH_HLEN] & 0x0f) * 4;
                const uint8_t *dns = d + ETH_HLEN + ihl + 8;
                int dnslen = hd->caplen - (ETH_HLEN + ihl + 8);
                if (dnslen < 12) continue;
                if (((dns[0]<<8)|dns[1]) != txid) continue;      /* match our query */
                char curstr[256]; wire_to_str(cur, curstr);
                queries++;
                if (find_nsec_next(dns, dnslen, next, &nextl)) {
                    char ns[256]; wire_to_str(next, ns);
                    printf("  query %-22s NSEC  ->  next = %s\n", curstr, ns);
                    got = 1;
                } else {
                    printf("  query %-22s NSEC  ->  no NSEC in reply (chain broken)\n", curstr);
                    got = 2;
                }
                break;
            }
        }
        if (got == 0) { printf("  (no reply for %s)\n", (char[256]){0}); break; }
        if (got == 2) break;                       /* NSEC3 / no NSEC: walk blocked */
        if (wire_eq(next, apexw)) { printf("  wrapped back to %s - zone fully walked\n", apex); break; }
        wire_to_str(next, recovered[nrec]); nrec++;
        memcpy(cur, next, nextl); curl = nextl;
    }

    printf("\n[zonewalk] %d queries, recovered %d name(s):\n", queries, nrec);
    for (int i = 0; i < nrec; i++) printf("    %s\n", recovered[i]);
    pcap_close(h);
    return 0;
}
