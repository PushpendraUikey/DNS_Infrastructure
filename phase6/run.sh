#!/bin/sh
# Phase 6 orchestration, run from the host in the phase6/ directory after:
#     ./sign.sh && docker compose up --build -d
#
#   ./run.sh verify   - interceptor relays transparently; client gets the real page
#   ./run.sh attack   - forge the resolver->client reply; test both clients:
#                         Client A = ordinary stub (dig/curl)   -> hijacked
#                         Client B = delv with the root anchor  -> catches it
#   ./run.sh reset    - stop interceptor, turn off the diversion
#
# The diversion lives on the edge-router (client-bound replies via the attacker)
# and the attacker sits at 172.16.1.100 on the client subnet.

start() {   # $1 = relay|forge
    docker exec attacker pkill interceptor 2>/dev/null || true
    docker exec edge-router sh /scripts/undivert.sh >/dev/null 2>&1 || true
    docker exec -d attacker sh -c "/usr/local/bin/interceptor $1 eth0 > /tmp/$1.log 2>&1"
    sleep 2
    docker exec edge-router sh /scripts/divert.sh >/dev/null
}

case "$1" in
    verify)
        start relay
        echo "example.com -> $(docker exec client dig example.com +short)"
        echo -n "curl example.com: "
        docker exec client curl -s --max-time 5 http://example.com | grep -iE "welcome|hijack"
        ;;
    attack)
        start forge
        echo "===== Client A : ordinary stub (dig / curl) ====="
        docker exec client dig example.com | grep -E "status:|flags:|IN[[:space:]]+A"
        echo -n "curl http://example.com -> "
        docker exec client curl -s --max-time 5 http://example.com | grep -iE "welcome|hijack"
        echo ""
        echo "===== Client B : locally-validating (delv, holds the root key) ====="
        docker exec client delv -a /etc/bind/trust-anchor.conf @172.16.2.10 example.com 2>&1 | head -4
        ;;
    reset)
        docker exec attacker pkill interceptor 2>/dev/null || true
        docker exec edge-router sh /scripts/undivert.sh >/dev/null 2>&1 || true
        echo "reset done"
        ;;
    *) echo "usage: $0 {verify|attack|reset}"; exit 1 ;;
esac
