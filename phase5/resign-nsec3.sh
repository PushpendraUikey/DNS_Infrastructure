#!/bin/sh
# The fix: re-sign example.com with NSEC3 instead of NSEC, REUSING the existing
# example.com keys (so the DS already published in com still matches and the
# chain of trust stays intact). Only domain-ns changes; root and com are
# untouched. Run ./sign.sh first, then this, then restart domain-ns.
set -e
cd "$(dirname "$0")"
docker run --rm -v "$PWD:/work" -w /work --entrypoint sh \
    internetsystemsconsortium/bind9:9.20 -c '
set -e
cd /work
cp domain-ns/db.example.com build/db.example.com
# -3 <salt> turns on NSEC3; -H 0 = no extra iterations (current best practice)
dnssec-signzone -3 ABCDEF01 -H 0 -S -K keys/example -o example.com -O full \
    -f domain-ns/db.example.com.signed build/db.example.com
echo "re-signed example.com with NSEC3 (keys reused, DS unchanged)"
'
