#!/bin/sh
# Stand up a private CA and issue the resolver's certificate.
# The resolver cert's only identity is the DNS name resolver.cs6008.local
# (a SAN, no IP SAN), so the client can only validate it when it connects by
# that name. Also makes a ROGUE cert (same name, different/self CA) used by the
# attacker in attempt (ii). Run before 'docker compose up'. Keys stay out of git.
set -e
cd "$(dirname "$0")"
docker run --rm -v "$PWD/pki:/pki" -w /pki alpine:3.20 sh -c '
set -e
apk add --no-cache openssl >/dev/null

# --- private CA ---
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 3650 \
    -subj "/CN=CS6008 DNS Lab Root CA"

# --- resolver certificate, signed by our CA, SAN = the DNS name only ---
openssl req -newkey rsa:2048 -nodes -keyout resolver.key -out resolver.csr \
    -subj "/CN=resolver.cs6008.local"
printf "subjectAltName=DNS:resolver.cs6008.local\n" > san.cnf
openssl x509 -req -in resolver.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out resolver.crt -days 825 -extfile san.cnf

# --- rogue certificate: same name, but self-signed (NOT our CA) ---
openssl req -x509 -newkey rsa:2048 -nodes -keyout rogue.key -out rogue.crt -days 825 \
    -subj "/CN=resolver.cs6008.local" \
    -addext "subjectAltName=DNS:resolver.cs6008.local"

rm -f resolver.csr san.cnf .srl ca.srl 2>/dev/null || true
echo "== generated =="
echo "resolver cert SAN:"; openssl x509 -in resolver.crt -noout -ext subjectAltName
echo "rogue cert issuer (self, untrusted):"; openssl x509 -in rogue.crt -noout -issuer
'
