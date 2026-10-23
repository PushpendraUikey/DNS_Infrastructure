#!/bin/sh
# Offline DNSSEC signing for the whole hierarchy.
#
# Runs inside a BIND container (see sign.sh) with the phase3 directory mounted
# at /work. Zones are signed child -> parent so that each child's DS record
# exists before its parent zone is signed:
#
#     example.com  ->  DS into com  ->  DS into root
#
# Outputs (all regenerated, none committed):
#   domain-ns/db.example.com.signed
#   tld-ns/db.com.signed
#   root-ns/db.root-zone.signed
#   resolver/trust-anchor.conf        (the root KSK, the resolver's one anchor)
set -e

ALGO=ECDSAP256SHA256
cd /work

echo "== cleaning previous signing output =="
rm -rf keys build
mkdir -p keys/root keys/com keys/example build
rm -f domain-ns/db.example.com.signed tld-ns/db.com.signed \
      root-ns/db.root-zone.signed resolver/trust-anchor.conf dsset-* 2>/dev/null || true

# --- example.com (leaf) ---
echo "== signing example.com =="
KSK_E=$(dnssec-keygen -a $ALGO -f KSK -n ZONE -K keys/example example.com)
dnssec-keygen -a $ALGO -n ZONE -K keys/example example.com >/dev/null
cp domain-ns/db.example.com build/db.example.com
dnssec-signzone -S -K keys/example -o example.com -O full \
    -f domain-ns/db.example.com.signed build/db.example.com
dnssec-dsfromkey -2 keys/example/$KSK_E.key > build/ds.example.com

# --- com (parent of example.com) ---
echo "== signing com =="
KSK_C=$(dnssec-keygen -a $ALGO -f KSK -n ZONE -K keys/com com)
dnssec-keygen -a $ALGO -n ZONE -K keys/com com >/dev/null
cp tld-ns/db.com build/db.com
cat build/ds.example.com >> build/db.com         # secure delegation to example.com
dnssec-signzone -S -K keys/com -o com -O full \
    -f tld-ns/db.com.signed build/db.com
dnssec-dsfromkey -2 keys/com/$KSK_C.key > build/ds.com

# --- root (parent of com) ---
echo "== signing root =="
KSK_R=$(dnssec-keygen -a $ALGO -f KSK -n ZONE -K keys/root .)
dnssec-keygen -a $ALGO -n ZONE -K keys/root . >/dev/null
cp root-ns/db.root-zone build/db.root
cat build/ds.com >> build/db.root                # secure delegation to com
dnssec-signzone -S -K keys/root -o . -O full \
    -f root-ns/db.root-zone.signed build/db.root

# --- resolver trust anchor = the root KSK (public key only) ---
echo "== writing resolver trust anchor (root KSK) =="
awk '/DNSKEY/ {
        for (i = 1; i <= NF; i++)
            if ($i == "DNSKEY") {
                f = $(i+1); p = $(i+2); a = $(i+3); k = "";
                for (j = i+4; j <= NF; j++) k = k $j;
                printf "trust-anchors {\n    \".\" static-key %s %s %s \"%s\";\n};\n", f, p, a, k;
                exit;
            }
    }' keys/root/$KSK_R.key > resolver/trust-anchor.conf

rm -f dsset-* 2>/dev/null || true
echo "== done =="
echo "signed zones:"; ls -1 domain-ns/*.signed tld-ns/*.signed root-ns/*.signed
echo "trust anchor:"; cat resolver/trust-anchor.conf
