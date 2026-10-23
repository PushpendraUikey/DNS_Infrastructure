# Phase 5 — Zone Walking

A signed zone must prove that a name does *not* exist, and that proof is signed
**ahead of time**. A pre-signed denial can't be about the queried name itself, so it
names the gap between two names that *do* exist ("nothing exists between `mail` and
`ns`"). Follow that chain and it hands you every name in the zone — including hosts
that are never advertised. This phase walks the zone through NSEC, then closes the
leak with NSEC3.

## What's in the zone

`domain-ns/db.example.com` carries the public names (`@`, `www`, `ns`) plus five
**unadvertised** internal hosts that are the walk targets:

```
dev     A 10.10.0.11
vpn     A 10.10.0.12
mail    A 10.10.0.13
db      A 10.10.0.14
backup  A 10.10.0.15
```

The zone is signed with **plain NSEC** (`signer.sh`, no `-3`) — that is the signing
choice that makes authenticated denial walkable.

## What's new vs Phase 3

- **`attacker/zonewalk.c`** — a C/libpcap NSEC walker (built alongside the interceptor).
  It queries the authoritative server directly for each name's NSEC record, reads the
  "next name" field, and repeats until the chain wraps to the apex. DNS queries only —
  no AXFR, no wordlist.
- **`resign-nsec3.sh`** — the fix: re-sign `example.com` with NSEC3, **reusing the
  existing keys** so the DS already published in `com` still matches and the chain of
  trust stays intact. Only `domain-ns` changes.
- **`run.sh`** — `verify` | `walk` | `fix`.

## ⚠️ Signer runs first

As in Phase 3, the `.signed` zones and trust anchor are generated, not committed:

```sh
./sign.sh
docker compose up --build -d
```

## Verify — show the signed denial

```sh
./run.sh verify
```

Queries `nonexistent.example.com +dnssec` and shows the **NSEC** record that proves
non-existence by pointing at the surrounding names.

## Attack — walk the zone

```sh
./run.sh walk
```

Starting from knowledge of `example.com` alone, `zonewalk` follows the NSEC chain:

```
example.com → backup → db → dev → mail → ns → vpn → www → (wraps to apex)
```

It recovers all owner names — the five hidden hosts included — in `names + 2` queries
or fewer, printing the recovered list at the end.

## Fix — NSEC3, then re-walk

```sh
./run.sh fix        # re-sign with NSEC3 (keys reused, DS unchanged), reload domain-ns
./run.sh walk       # same walker now recovers nothing
```

After the fix, a type-NSEC query returns **NSEC3** records instead of NSEC, so the
walker finds no next-name to follow (`chain broken`) and recovers zero — while a
nonexistent name still gets an authenticated NSEC3 denial.

To return to the walkable state: `./sign.sh && docker restart domain-ns`.

## Reset / teardown

```sh
docker compose down
```
