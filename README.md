# DNS_Lab

**CS6008: Network Security — Assignment 2: DNS Security**

A small, self-contained DNS hierarchy built in Docker containers. We deploy plain
hierarchical DNS, attack it from an on-path position, and then add defenses one layer at
a time to see which attacks each one actually stops. Each phase has its own directory
with its own `compose.yml`, configs, scripts, attack source, and a `README.md`; this file
is the overview and the common conventions.

## Team

| Roll No | Name |
|---------|------|
| 23b0945 | Akshit Kumar |
| 23b1023 | Puspendra Uikey |

## Topology

Three isolated `/24` bridge subnets, joined only by two router containers. No node except
the two routers forwards traffic; isolation comes from the topology.

| Container | Subnet | Address | Role |
|-----------|--------|---------|------|
| client | client | 172.16.1.10 | Issues lookups and web requests |
| webserver | client | 172.16.1.20 | Serves the real example.com page |
| rogue-web | client | 172.16.1.30 | Adversary's page (Phase 2+) |
| resolver | resolver | 172.16.2.10 | Recursive resolver; validates from Phase 3 |
| root-ns | authoritative | 172.16.3.10 | Authoritative for `.` |
| tld-ns | authoritative | 172.16.3.20 | Authoritative for `com` |
| domain-ns | authoritative | 172.16.3.30 | Authoritative for `example.com` |
| edge-router | client + resolver | 172.16.1.2 / 172.16.2.2 | client ↔ resolver |
| core-router | resolver + auth | 172.16.2.3 / 172.16.3.3 | resolver ↔ authoritative |
| attacker | resolver (P2–5) / client (P6–7) | 172.16.2.100 / 172.16.1.100 | On-path adversary |

Only the routers enable IP forwarding (no NAT). Every other node drops its default route
in `entrypoint.sh` and installs only the static routes it needs through its router. The
attacker additionally holds `NET_RAW` for libpcap capture/injection and never forwards in
the kernel (`ip_forward=0`), so diverted packets reach only its interceptor.

## Tooling

- Docker + Docker Compose for orchestration.
- BIND 9.20 on every nameserver and the resolver.
- All attack programs are C with libpcap (`pcap_inject`) — no Scapy/dnspython.
- `dig`, `delv`, `kdig`, `curl`, `openssl`, `tcpdump` for verification.

## Conventions

- **Phases 3–7 are signed.** Run `./sign.sh` **before** `docker compose up` — the signed
  zones and trust anchor are generated, not committed, and compose bind-mounts them. If you
  bring the stack up first, Docker creates empty mount dirs and `named` fails to load.
- **Phase 7 also needs `./make-certs.sh`** (the private CA + resolver/rogue certificates)
  before the stack comes up.
- Each phase has a `run.sh` with `verify` (transparent/benign) and an attack subcommand,
  plus `reset`. The diversion is a single route added on a router (`scripts/divert.sh`),
  removed by `undivert.sh`.
- Generated artifacts (signed zones, DNSSEC keys, TLS keys/certs, compiled binaries, built
  images) are not committed; `.gitignore` excludes them and the grader rebuilds from source.

## Phases

### Phase 1 — Building the DNS Hierarchy
Plain hierarchical DNS, no attacker. root → com → example.com, recursive resolver with
validation off, client fetches the real page. Proves correctness and topology isolation.
```sh
cd phase1 && docker compose up -d --build
docker compose exec client dig example.com +short       # 172.16.1.20
docker compose exec client dig @172.16.3.10 example.com  # network unreachable (isolated)
```

### Phase 2 — On-Path Response Forgery
Attacker on the resolver subnet; core-router diverts the resolver's replies through it; the
C/libpcap interceptor rewrites the example.com answer to rogue-web. Plain DNS trusts any
reply, and the on-path position hands the attacker the id/port/question for free.
```sh
cd phase2 && docker compose up -d --build
./run.sh verify     # relay: example.com -> 172.16.1.20 (real)
./run.sh attack     # forge: example.com -> 172.16.1.30, www still -> 172.16.1.20
```

### Phase 3 — DNSSEC Chain of Trust
Each zone signs itself; DS records chain the zones; the resolver validates against the root
KSK as its one trust anchor. The unchanged Phase 2 attack now fails.
```sh
cd phase3 && ./sign.sh && docker compose up -d --build
./run.sh verify     # ad flag + RRSIG + delv validates
./run.sh attack     # forged A fails validation -> SERVFAIL; www still validates
```

### Phase 4 — Signature Stripping & Downgrade
The attacker can't forge a signature, so it strips the DNSSEC records to make the zone look
unsigned. Run A (secure delegation) refuses the downgrade; Run B (parent publishes no DS)
reopens the attack.
```sh
cd phase4 && ./sign.sh && docker compose up -d --build
./run.sh runA                        # secure: SERVFAIL
./sign.sh nods && ./run.sh reload
./run.sh runB                        # insecure delegation: hijack to 172.16.1.30
```

### Phase 5 — Zone Walking
A signed zone proves non-existence with pre-signed NSEC records that point at the next real
name — so following the chain enumerates the whole zone, including hidden hosts. NSEC3
closes the online walk.
```sh
cd phase5 && ./sign.sh && docker compose up -d --build
./run.sh verify     # signed denial (NSEC) for a nonexistent name
./run.sh walk       # recovers dev, vpn, mail, db, backup, ...
./run.sh fix        # re-sign with NSEC3, reload
./run.sh walk       # now recovers nothing
```

### Phase 6 — Last-Mile Response Forgery
DNSSEC validates at the resolver, but the resolver→client hop carries no proof. The attacker
moves to the client subnet and forges that last reply. An ordinary stub is hijacked; a
locally-validating client (delv with the root key) catches it.
```sh
cd phase6 && ./sign.sh && docker compose up -d --build
./run.sh verify     # relay: client gets the real page
./run.sh attack     # Client A (stub) hijacked; Client B (delv) rejects as bogus
```

### Phase 7 — Encrypting the Last Mile (DoT / DoH)
A private CA issues the resolver a certificate for `resolver.cs6008.local`; the client
installs the CA and resolves over DoH/DoT by name, validating the cert. Three attacks
(alter in transit, rogue certificate, deny the transport) are run against a strict and a
permissive client — only forcing a cleartext downgrade against the permissive client lands.
```sh
cd phase7 && ./make-certs.sh && ./sign.sh && docker compose up -d --build
./run.sh verify     # DoH resolution, cert validates, no cleartext on edge-router
./run.sh i          # alter in transit  -> both safe
./run.sh ii         # rogue certificate -> both safe (cert rejected)
./run.sh iii        # deny transport    -> permissive client downgrades and is hijacked
```

## Reset / teardown

Each phase: `./run.sh reset` (where present) then `docker compose down`.

## Repository layout

```
phase1/ .. phase7/   # one self-contained directory per phase (compose, configs, scripts, attack source, README)
report.pdf           # one section per phase: design, evidence, report answers
```