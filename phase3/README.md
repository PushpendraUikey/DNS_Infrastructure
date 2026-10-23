# Phase 3 — DNSSEC Chain of Trust

The Phase 2 hierarchy, now cryptographically signed, with a validating resolver.
Each zone signs itself, each parent vouches for its child with a DS record, and
the resolver checks the whole chain against one trust anchor — our root KSK. The
**unchanged** Phase 2 attacker is then re-run against it: the on-path forgery that
hijacked `example.com` in Phase 2 now fails validation and the client gets nothing.

## What changed from Phase 2

- **Zones are signed offline** (`sign.sh` → `signer.sh`): `example.com`, `com`, and
  the root each get a KSK + ZSK and a `.signed` zone file.
- **DS records chain the zones**: `example.com`'s DS is published in `com`, `com`'s DS
  in the root — an unbroken chain from the root key down to `example.com`.
- **Resolver validates**: `dnssec-validation yes` plus the root KSK as the single
  `static-key` trust anchor (`trust-anchor.conf`). Root hints unchanged.
- **Attacker is byte-for-byte Phase 2** — same `interceptor.c`, same `forge` mode,
  same divert route. Nothing about the adversary changes; only the zones and resolver do.

## ⚠️ Run the signer FIRST

The signed zone files and the trust anchor are **generated, not committed** (keys and
signatures never belong in the repo). `compose.yml` bind-mounts them, so they must exist
*before* the stack comes up. Always:

```sh
./sign.sh                       # generates *.signed zones + resolver/trust-anchor.conf
docker compose up --build -d
```

If you run `docker compose up` without signing first, Docker will create the missing
mount sources as empty directories and `named` will fail to load its zone. If that
happens: `docker compose down`, remove the stray empty dirs, run `./sign.sh`, and bring
the stack up again.

`sign.sh` signs in a throwaway BIND container and uses `ECDSAP256SHA256` (compact
signatures, modern, widely supported). Signing order is child → parent so each child's
DS exists before its parent is signed.

## Layout

```
phase3/
├── sign.sh / signer.sh       # offline DNSSEC signing for the whole hierarchy
├── compose.yml               # Phase 2 topology + mounts for *.signed and trust anchor
├── Dockerfile, entrypoint.sh # base image + per-role routing (unchanged)
├── root-ns/   {named.conf (serves db.root-zone.signed), db.root-zone}
├── tld-ns/    {named.conf (serves db.com.signed),        db.com}
├── domain-ns/ {named.conf (serves db.example.com.signed), db.example.com}
├── resolver/  {named.conf (validation on + trust anchor), db.root, trust-anchor.conf*}
├── attacker/  {Dockerfile, interceptor.c}   # identical to Phase 2
├── scripts/   {divert.sh, undivert.sh}
├── web/ , rogue-web/
└── run.sh                     # verify | attack | reset
        (* trust-anchor.conf and *.signed are produced by sign.sh, not committed)
```

## Deploy

```sh
./sign.sh
docker compose up --build -d
docker compose ps              # all containers "running"
```

## Verify (healthy signed hierarchy, no attacker)

```sh
./run.sh verify
```

This runs, from the client:
- `dig +dnssec example.com` → expect the **`ad`** (authenticated-data) flag and an **RRSIG**.
- `delv @172.16.2.10 example.com` against the root trust anchor → expect **full validation**.

> Note: if `delv` rejects the `+root=.` option in `run.sh`, drop it — the `-a <anchor>`
> argument is what supplies the trust anchor.

## Attack (re-run the unchanged Phase 2 forge)

```sh
./run.sh attack
```

Flushes the cache, starts the interceptor in **forge** mode, switches the diversion on,
then queries from the client:
- `example.com` → the forged A fails signature validation → **SERVFAIL** (no rogue page).
- `www.example.com` → not targeted → still **validates** normally.

The forge overwrites the A record but not its RRSIG, so the signature no longer matches
the data — which is exactly what the resolver rejects.

## Reset / teardown

```sh
./run.sh reset                 # stop interceptor, undivert, flush cache
docker compose down
```

## Notes for the report

- **What the resolver checks:** the RRSIG over the `example.com` A RRset, up the DS/DNSKEY
  chain to the root trust anchor. The forged A breaks that signature → bogus → SERVFAIL.
- **What the attacker can still read:** everything — DNSSEC signs, it does not encrypt.
  Compare the attacked capture with Phase 1: the same cleartext is visible on the wire.
- **So DNSSEC protects** integrity and origin authenticity, **not** confidentiality — which
  is what Phase 7 (DoT/DoH) goes on to address.
- **Keys in the repo:** no private key is committed. `.gitignore` excludes `K*.private`,
  `K*.key`, `*.signed`, and `dsset-*`; the trust anchor holds only the public root KSK.