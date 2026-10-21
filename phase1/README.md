# Phase 1 — Building the DNS Hierarchy

A three-tier authoritative hierarchy (root → `com` → `example.com`), a recursive
resolver, a client, and a webserver, split across three isolated Docker bridge
subnets joined only by two router containers. No attacker, no DNSSEC — this is the
plain-DNS baseline every later phase builds on.

## Topology

| Container    | Subnet        | Address        | Role                                        |
|--------------|---------------|----------------|---------------------------------------------|
| client       | client        | 172.16.1.10    | Issues lookups and web requests             |
| webserver    | client        | 172.16.1.20    | Serves the real `example.com` page over HTTP |
| edge-router  | client+resolver | 172.16.1.2 / 172.16.2.2 | Routes client ↔ resolver (forwards)   |
| resolver     | resolver      | 172.16.2.10    | Recursive caching resolver (validation off) |
| core-router  | resolver+auth | 172.16.2.3 / 172.16.3.3 | Routes resolver ↔ authoritative (forwards) |
| root-ns      | authoritative | 172.16.3.10    | Authoritative for the root zone `.`         |
| tld-ns       | authoritative | 172.16.3.20    | Authoritative for `com`                     |
| domain-ns    | authoritative | 172.16.3.30    | Authoritative for `example.com`             |

Only the two routers enable IP forwarding (`net.ipv4.ip_forward=1`, no NAT). Every
other node drops its Docker default route in `entrypoint.sh` and installs only the
static routes it needs through the router on its segment, so no subnet can reach
another except through a router. BIND 9.20 runs on every nameserver and the resolver.

## Layout

```
phase1/
├── compose.yml              # the 8 containers + 3 bridge networks
├── Dockerfile               # ISC bind9:9.20 base + curl, python3, tcpdump, iproute2
├── entrypoint.sh            # per-role static routes (keyed on $NODE_ROLE)
├── root-ns/{named.conf,db.root-zone}
├── tld-ns/{named.conf,db.com}
├── domain-ns/{named.conf,db.example.com}
├── resolver/{named.conf,db.root}     # recursive; db.root = hints → our root-ns
├── web/index.html           # the real example.com page
├── logs/phase1_verification.txt      # captured verification transcript
└── captures/phase1_referral.pcap     # referral chain capture (open in Wireshark)
```

## Deploy

From `phase1/`:

```sh
docker compose up -d --build
docker compose ps          # all 8 containers should be "running"
```

Routes install automatically at container start; no manual step is needed.

## Verify

All four checks below are captured in `logs/phase1_verification.txt`.

**1. Forward resolution + real page (from client):**
```sh
docker compose exec client dig example.com +short        # -> 172.16.1.20
docker compose exec client dig www.example.com +short    # -> 172.16.1.20
docker compose exec client curl -s http://example.com    # -> the real page
```

**2. Isolation — the authoritative subnet is not directly reachable from client:**
```sh
docker compose exec client dig @172.16.3.10 example.com
# -> "network unreachable": client has no route to 172.16.3.0/24
```

**3. Static routes (show the client has no default and no auth-subnet route):**
```sh
docker compose exec client   ip route
docker compose exec resolver ip route
```

**4. Capture one full resolution on core-router (resolver ↔ authoritative):**

In one terminal, start the capture on core-router:
```sh
docker compose exec core-router tcpdump -ni any -w /tmp/phase1_referral.pcap port 53
```
In another, flush the resolver cache and trigger a fresh lookup:
```sh
docker compose exec resolver rndc flush 2>/dev/null || docker compose restart resolver
docker compose exec client dig example.com
```
Stop the capture (Ctrl-C) and copy it out:
```sh
docker compose cp core-router:/tmp/phase1_referral.pcap ./captures/phase1_referral.pcap
```
The trace shows the referral chain: resolver → **root-ns** (referral to `com`) →
**tld-ns** (referral to `example.com`) → **domain-ns** (answer `A 172.16.1.20`).

## Teardown

```sh
docker compose down
```

## Notes

- The resolver sets `dnssec-validation no` deliberately — with `auto` it would try
  the real root's built-in trust anchor against our private root and fail.
- All addresses are real end to end; the capture shows source IPs preserved
  (e.g. `172.16.2.10 > 172.16.3.10`), confirming no NAT on the router path.