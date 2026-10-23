# Phase 4 — Signature Stripping & Downgrade

Phase 3 showed that forging a *signed* answer fails — the attacker can't fake a
signature. Phase 4 asks the next question: instead of faking a signature, what if
the attacker **strips the signatures off** and makes the zone look like it was never
signed? If the resolver no longer expects DNSSEC on `example.com`, the plain Phase 2
forgery is accepted again.

The answer turns out to depend entirely on **one record in the parent** — the DS. This
phase proves it with a two-run A/B experiment against the *same* attack.

## What changed from Phase 3

- **Attacker gains a `strip` mode** (`attacker/interceptor.c`): for an `example.com`
  reply, it rebuilds the whole message with every DNSSEC record removed
  (RRSIG/DNSKEY/DS/NSEC/NSEC3) and the A rewritten to rogue-web, so the response looks
  unsigned. `relay` and `forge` modes are unchanged.
- **Signer takes a `nods` flag** (`sign.sh` / `signer.sh`): with it, `com` is signed but
  publishes **no DS for example.com** — the operator signed the child yet never gave the
  DS to the parent. Without it, the delegation is secure, exactly as in Phase 3.
- **`run.sh` gains `runA` / `runB` / `reload`**: the two attack runs plus a helper to
  restart the servers after a re-sign.
- Resolver, routers, divert scripts: unchanged from Phase 3.

## The two runs

| | Delegation | What the attacker does | Expected result |
|-----|-----------|------------------------|-----------------|
| **Run A** | **secure** — `com` publishes `example.com`'s DS | strip signatures (+ the DS from the `com` referral) and forge the A | **SERVFAIL** — downgrade refused |
| **Run B** | **insecure** — `com` publishes *no* DS for `example.com` | same strip-and-forge | **hijack** — client gets `172.16.1.30` |

The only difference between the runs is that one DS record. That is the whole point.

## ⚠️ Signer runs first (same as Phase 3)

The `.signed` zones and trust anchor are generated, not committed. Run `./sign.sh`
before bringing the stack up, or Docker will create empty mount dirs and `named` will
fail to load its zones.

## Run A — secure delegation (downgrade fails)

```sh
./sign.sh                       # secure: com publishes example.com's DS
docker compose up --build -d

./run.sh verify                 # example.com resolves, authenticated (ad flag)
./run.sh runA                   # strip + forge against the secure delegation
```

Expected: `example.com` → **SERVFAIL**, no rogue page. The resolver was told (by the DS
in `com`) that `example.com` is signed, so a stripped, signature-less answer looks
bogus and is rejected. Stripping the DS from the referral doesn't help — the DS the
resolver trusts lives inside the *signed `com` zone*, which the attacker can't forge.

## Run B — insecure delegation (downgrade succeeds)

Re-sign with the parent DS omitted, reload the servers, then mount the same attack:

```sh
./sign.sh nods                  # com is signed but omits example.com's DS
./run.sh reload                 # restart root-ns, tld-ns, domain-ns, resolver
./run.sh verify                 # example.com now resolves WITHOUT the ad flag (insecure)
./run.sh runB                   # same strip + forge
```

Expected: `example.com` → **172.16.1.30** (rogue) returned by the *validating* resolver.
With no DS in the parent, nothing tells the resolver `example.com` should be signed, so
it treats the zone as unsigned, ignores the signatures that are actually there, and
accepts the forgery.

## Reset / teardown

```sh
./run.sh reset                  # stop interceptor, undivert, flush cache
docker compose down
```

To go back to Run A after Run B: `./sign.sh && ./run.sh reload`.
