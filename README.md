# DNS_Lab

**CS6008: Network Security — Assignment 2: DNS Security**


A small, self-contained DNS hierarchy built in Docker containers. We deploy
plain hierarchical DNS, attack it from an on-path position, and then add
defenses one layer at a time to see which attacks each one actually stops.

## Team

| Roll No | Name |
|-----------|-----------------|
| 23b0945 | Akshit Kumar |
| 23b1023 | Puspendra Uikey |

## Overview

The project is split into seven phases, each with something to deploy,
something to verify, and questions answered in the report:

1. **Building the DNS Hierarchy** — deploy plain hierarchical DNS (root → com → example.com).
2. **On-Path Response Forgery** — poison the resolver's cache to hijack a name.
3. **DNSSEC Chain of Trust** — add signing + validation and re-run the attack.
4. **Signature Stripping & Downgrade** — make a signed zone look unsigned.
5. **Zone Walking** — enumerate a signed zone through authenticated denial, then close the leak.
6. **Last-Mile Response Forgery** — forge replies where DNSSEC's guarantee runs out.
7. **Encrypting the Last Mile (DoT/DoH)** — authenticate and encrypt the client–resolver link.
