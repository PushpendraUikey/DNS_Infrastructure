#!/bin/sh
# Phase 3 orchestration, run from the host in the phase3/ directory after:
#     ./sign.sh && docker compose up --build -d
#
#   ./run.sh verify   - no attacker: validated resolution (AD flag + delv)
#   ./run.sh attack   - re-run the unchanged Phase 2 forge against the signed zone
#   ./run.sh reset    - stop the interceptor, turn off the diversion, flush the cache

ready() {
    n=0
    until [ -n "$(docker exec client dig @172.16.2.10 . NS +time=1 +tries=1 +short 2>/dev/null)" ]; do
        n=$((n + 1)); [ "$n" -gt 25 ] && break; sleep 1
    done
}

case "$1" in
    verify)
        docker exec attacker pkill interceptor 2>/dev/null || true
        docker exec core-router sh /scripts/undivert.sh >/dev/null 2>&1 || true
        docker restart resolver >/dev/null; ready
        echo "== dig +dnssec example.com (expect 'ad' flag + an RRSIG) =="
        docker exec client dig +dnssec example.com | grep -E "flags:|RRSIG|IN A|status:"
        echo
        echo "== delv example.com against the root trust anchor (expect 'fully validated') =="
        docker exec client delv -a /etc/bind/trust-anchor.conf +root=. @172.16.2.10 example.com 2>&1 | head -6
        ;;
    attack)
        docker exec attacker pkill interceptor 2>/dev/null || true
        docker exec core-router sh /scripts/undivert.sh >/dev/null 2>&1 || true
        docker restart resolver >/dev/null; ready
        docker exec -d attacker sh -c '/usr/local/bin/interceptor forge eth0 > /tmp/forge.log 2>&1'
        sleep 2
        docker exec core-router sh /scripts/divert.sh >/dev/null
        echo "== example.com (forged A should FAIL validation -> SERVFAIL) =="
        docker exec client dig example.com | grep -E "status:|IN A"
        echo "== www.example.com (not targeted -> still validates) =="
        docker exec client dig www.example.com | grep -E "status:|IN A"
        ;;
    reset)
        docker exec attacker pkill interceptor 2>/dev/null || true
        docker exec core-router sh /scripts/undivert.sh >/dev/null 2>&1 || true
        docker restart resolver >/dev/null
        echo "reset: interceptor stopped, diversion off, cache flushed"
        ;;
    *) echo "usage: $0 {verify|attack|reset}"; exit 1 ;;
esac
