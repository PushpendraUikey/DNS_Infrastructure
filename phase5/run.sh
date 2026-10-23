#!/bin/sh
# Phase 5 orchestration, run from the host in the phase5/ directory after:
#     ./sign.sh && docker compose up --build -d
#
#   ./run.sh verify   - show the signed denial for a name that does not exist
#   ./run.sh walk     - run the C/libpcap NSEC walker (recovers the hidden names)
#   ./run.sh fix      - re-sign example.com with NSEC3 and reload domain-ns
#   ./run.sh walk     - (after fix) same walker now recovers nothing

case "$1" in
    verify)
        echo "== a name that does not exist, with +dnssec =="
        docker exec client dig +dnssec +multiline nonexistent.example.com @172.16.2.10 \
            | grep -iE "status:|NSEC|flags:" | head -8
        ;;
    walk)
        docker exec attacker /usr/local/bin/zonewalk example.com eth0
        ;;
    fix)
        ./resign-nsec3.sh
        docker restart domain-ns >/dev/null
        sleep 3
        echo "domain-ns reloaded with the NSEC3 zone"
        echo "== a nonexistent name still gets an authenticated denial (now via NSEC3) =="
        docker exec client dig +dnssec nonexistent.example.com @172.16.2.10 \
            | grep -iE "status:|NSEC3|flags:" | head -6
        ;;
    *) echo "usage: $0 {verify|walk|fix}"; exit 1 ;;
esac
