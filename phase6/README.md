# Phase 6 — Last-Mile Response Forgery

DNSSEC validation happens **at the resolver**, but the link from the resolver to the
client carries no proof of it — the stub trusts whatever appears to come from its
resolver. This phase moves the adversary onto the **client subnet** and forges the reply
in that last hop, where DNSSEC's guarantee has run out. An ordinary stub is hijacked; a
client that validates for itself catches it.

## What's new vs Phase 3

- **Attacker relocated** to `172.16.1.100` on the **client subnet** (`entrypoint.sh`
  `attacker` role, `ip_forward=0`). Upstream (signed zones + validating resolver) is
  untouched.
- **Diversion on the edge-router** (`scripts/divert.sh`, run on edge-router):
  `ip route replace 172.16.1.10/32 via 172.16.1.100` sends the client-bound replies
  through the attacker. **No ARP spoofing; the client's own config is untouched.**
- **Interceptor retargeted** (`attacker/interceptor.c`): `VICTIM_IP=172.16.1.10` (client),
  `MY_IP=172.16.1.100`, filter `ip dst host 172.16.1.10`. `forge` mode rewrites the
  `example.com` A and leaves everything else (including DNSKEY/DS replies) unchanged.
- **`run.sh`**: `verify` | `attack` | `reset`.

## Deploy

```sh
./sign.sh                      # signed zones + trust anchor (as in Phase 3)
docker compose up --build -d
```

## Verify (relay — client still gets the real page)

```sh
./run.sh verify
# example.com -> 172.16.1.20, curl shows the real "welcome" page
```

## Attack (forge the last mile, test both clients)

```sh
./run.sh attack
```

- **Client A — ordinary stub (dig / curl).** Takes the forged answer at face value →
  resolves `example.com` to `172.16.1.30` and curls the **rogue** page. Hijack succeeds.
- **Client B — locally-validating (`delv` holding the root key as its own anchor).**
  Does its own validation: it still receives the genuine DNSKEY/DS chain (those replies
  aren't forged) but a forged A whose **RRSIG no longer matches** → reports the answer as
  **bogus** and refuses it. Catch succeeds.

The only on-the-wire change is the `example.com` A rdata; the RRSIG over it is left
intact, which is exactly what lets the validating client detect the tampering.

## Reset / teardown

```sh
./run.sh reset                 # stop interceptor, undivert
docker compose down
```