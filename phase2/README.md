# Phase 2 — On-Path Response Forgery

The plain-DNS hierarchy from Phase 1, now attacked. An on-path adversary sits on the
resolver subnet, the core-router is told to send the resolver's inbound replies through
it, and a C/libpcap interceptor rewrites the `example.com` answer to point at a rogue
webserver. Nothing on the real servers is touched — the attack lives entirely on the wire.

## Why it works

Plain DNS has no authentication: the resolver accepts whatever reply arrives first with
the right transaction id, port, and question. Because the attacker is **on-path**, it
reads the genuine reply and already knows all of those — so it doesn't guess a forgery,
it edits the real answer. Every other name resolves normally; only `example.com` is hijacked.

## What's new vs Phase 1

- **`attacker` role** (`entrypoint.sh`): an on-path node on the resolver subnet that does
  **not** forward in the kernel (`ip_forward=0`), so diverted replies dead-end at the
  libpcap interceptor instead of being relayed twice.
- **`attacker/` build** (`Dockerfile` + `interceptor.c`): compiles the interceptor with
  libpcap. `relay` mode forwards every reply unchanged; `forge` mode rewrites `example.com`
  A records to rogue-web and recomputes checksums.
- **`scripts/divert.sh` / `undivert.sh`** (run on core-router): add/remove the host route
  `172.16.2.10/32 via 172.16.2.100` that feeds the resolver's replies to the attacker.
- **`rogue-web`** (`172.16.1.30`): the hijack destination.
- **`run.sh`**: `verify` | `attack` | `reset`.

## Addresses

| Node | Address | |
|------|---------|--|
| resolver (victim) | 172.16.2.10 | |
| attacker | 172.16.2.100 | on-path, resolver subnet |
| webserver (real) | 172.16.1.20 | |
| rogue-web | 172.16.1.30 | forged target |

## Deploy

```sh
docker compose up --build -d
docker compose ps              # all containers "running"
```

## Verify (relay — proves the pipeline, no tampering)

```sh
./run.sh verify
# example.com -> 172.16.1.20, www.example.com -> 172.16.1.20 (both real)
```

Relay mode re-injects every reply unchanged. If `verify` shows the real address, the
divert route, ARP, checksums and injection are all working — only *then* does a failed
`attack` mean the forge logic, not the plumbing.

## Attack (forge)

```sh
./run.sh attack
# example.com     -> 172.16.1.30   (hijacked to rogue-web)
# www.example.com -> 172.16.1.20   (untouched, still real)
```

Then from the client, the fetch lands on the rogue page:

```sh
docker compose exec client curl -s http://example.com
```

`run.sh` flushes the resolver cache (restart) before starting, so a fresh upstream
lookup actually reaches the interceptor — DNS caching would otherwise serve the old
answer and the attacker would see nothing.

## Reset / teardown

```sh
./run.sh reset                 # stop interceptor, undivert, flush cache
docker compose down
```

## How the interception works

1. `divert.sh` on core-router routes replies for `172.16.2.10` to `172.16.2.100`.
2. The frames arrive at the attacker's NIC; with `ip_forward=0` the kernel drops them at
   the IP layer, but libpcap captures them first (`PCAP_D_IN`, filter `ip dst host 172.16.2.10`).
3. In `forge` mode, for an `example.com`/A reply (source port 53), the A rdata is
   overwritten with the rogue address.
4. Both IP and UDP checksums are recomputed — essential, because containers hand off
   packets with uncomputed (offloaded) checksums that the resolver would otherwise drop.
5. The frame is re-injected to the resolver's MAC.
