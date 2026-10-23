#!/bin/sh
# Sign the hierarchy offline using the BIND tools in a throwaway container.
# Run this once before "docker compose up --build -d".
set -e
cd "$(dirname "$0")"
# pass "nods" through for Run B (com signed without example.com's DS)
docker run --rm -v "$PWD:/work" -w /work \
    --entrypoint sh internetsystemsconsortium/bind9:9.20 /work/signer.sh "$1"
