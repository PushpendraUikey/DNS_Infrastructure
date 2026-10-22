#!/bin/sh
# Phase 4 orchestration, run from the host in the phase4/ directory.
#
# Setup for Run A (secure delegation):   ./sign.sh      && docker compose up --build -d
# Setup for Run B (no DS for example.com): ./sign.sh nods && (reload the servers)
#
#   ./run.sh verify   - no attacker: example.com resolves (authenticated under Run A)
#   ./run.sh runA     - strip+forge against the SECURE delegation  (expect SERVFAIL)
#   ./run.sh runB     - strip+forge against the INSECURE delegation (expect hijack 172.16.1.30)
#   ./run.sh reload   - restart the authoritative servers + resolver after a re-sign
#   ./run.sh reset    - stop interceptor, diversion off, flush cache

ready() {
    n=0
    until [ -n "$(docker exec client dig @172.16.2.10 . NS +time=1 +tries=1 +short 2>/dev/null)" ]; do
        n=$((n + 1)); [ "$n" -gt 25 ] && break; sleep 1
    done
}

strip_attack() {
    docker exec attacker pkill interceptor 2>/dev/null || true
    docker exec core-router sh /scripts/undivert.sh >/dev/null 2>&1 || true
    docker restart resolver >/dev/null; ready
    docker exec -d attacker sh -c '/usr/local/bin/interceptor strip eth0 > /tmp/strip.log 2>&1'
    sleep 2
    docker exec core-router sh /scripts/divert.sh >/dev/null
    docker exec client dig example.com >/dev/null 2>&1
}

case "$1" in
    verify)
        docker exec attacker pkill interceptor 2>/dev/null || true
        docker exec core-router sh /scripts/undivert.sh >/dev/null 2>&1 || true
        docker restart resolver >/dev/null; ready
        echo "== dig +dnssec example.com (Run A config: 'ad' set; Run B: no 'ad') =="
        docker exec client dig +dnssec example.com | grep -E "flags:|status:|IN[[:space:]]+A"
        ;;
    runA|runB)
        strip_attack
        echo "interceptor log:"; docker exec attacker sh -c 'grep -E "interceptor|STRIPPED" /tmp/strip.log | head'
        echo "example.com     -> status $(docker exec client dig example.com | grep -oE 'status: [A-Z]+' | head -1), addr $(docker exec client dig example.com +short)"
        echo "www.example.com -> $(docker exec client dig www.example.com +short)"
        echo -n "curl example.com: "
        P=$(docker exec client curl -s --max-time 5 http://example.com 2>/dev/null)
        [ -z "$P" ] && echo "FAILED (no hijack)" || echo "$P" | grep -iE "welcome|hijack"
        echo "resolver log:"; docker logs --since 40s resolver 2>&1 | grep -iE "no valid signature|RRSIG failed|insecurity|validated|NODATA" | tail -3
        ;;
    reload)
        docker restart root-ns tld-ns domain-ns resolver >/dev/null; ready
        echo "authoritative servers + resolver reloaded"
        ;;
    reset)
        docker exec attacker pkill interceptor 2>/dev/null || true
        docker exec core-router sh /scripts/undivert.sh >/dev/null 2>&1 || true
        docker restart resolver >/dev/null
        echo "reset done"
        ;;
    *) echo "usage: $0 {verify|runA|runB|reload|reset}"; exit 1 ;;
esac
