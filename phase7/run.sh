#!/bin/sh
# Phase 7 orchestration, run from the host in the phase7/ directory after:
#     ./make-certs.sh && ./sign.sh && docker compose up --build -d
#
#   ./run.sh verify   - resolve over DoH with the certificate validating cleanly
#   ./run.sh i        - attempt (i)  alter the answer in transit
#   ./run.sh ii       - attempt (ii) impersonate the resolver with a rogue cert
#   ./run.sh iii      - attempt (iii) deny the encrypted transport (force fallback)
#   ./run.sh reset    - stop interceptor/rogue server, undivert, unblock
#
# Each attempt is run against two clients:
#   strict     - DoH only, never falls back to cleartext
#   permissive - probes the encrypted transport; if it is DENIED it opportunistically
#                falls back to cleartext, but a bad certificate is a hard failure

DOH="https://resolver.cs6008.local/dns-query"
ATTACKER="172.16.1.100"

verdict() {
    if   echo "$1" | grep -qi hijack;  then echo "LANDED  (rogue page, 172.16.1.30)"
    elif echo "$1" | grep -qi welcome; then echo "safe    (real page)"
    else echo "no answer (failed closed)"; fi
}

strict()    { docker exec client curl -4 -s --max-time 6 "$@" --doh-url "$DOH" http://example.com 2>/dev/null; }

permissive() {
    docker exec client curl -4 -sS --max-time 5 "$@" https://resolver.cs6008.local/ -o /dev/null 2>/dev/null
    rc=$?
    if [ $rc -eq 7 ] || [ $rc -eq 28 ]; then          # transport denied -> opportunistic cleartext
        docker exec client curl -4 -s --max-time 6 http://example.com 2>/dev/null
    elif [ $rc -eq 0 ]; then                          # transport ok -> use DoH
        docker exec client curl -4 -s --max-time 6 "$@" --doh-url "$DOH" http://example.com 2>/dev/null
    fi                                                # anything else (bad cert) -> hard fail
}

forge_on() {
    docker exec attacker pkill interceptor 2>/dev/null || true
    docker exec -d attacker sh -c '/usr/local/bin/interceptor forge eth0 > /tmp/forge.log 2>&1'
    sleep 1
    docker exec edge-router sh /scripts/divert.sh >/dev/null
}
rogue_on() { docker exec -d attacker python3 /opt/rogue_server.py >/dev/null 2>&1; sleep 1; }
clean() {
    docker exec attacker pkill interceptor 2>/dev/null || true
    docker exec attacker pkill -f rogue_server 2>/dev/null || true
    docker exec edge-router sh /scripts/undivert.sh  >/dev/null 2>&1 || true
    docker exec edge-router sh /scripts/unblock443.sh >/dev/null 2>&1 || true
}

run_both() {
    echo "  strict  client (refuses cleartext) : $(verdict "$(strict $1)")"
    echo "  permissive client (allows fallback): $(verdict "$(permissive $1)")"
}

case "$1" in
    verify)
        clean
        echo "DoH resolution (strict client): $(verdict "$(strict)")"
        ;;
    i)
        clean; forge_on
        echo "(i) alter the answer in transit  [Do53 forge running; client speaks DoH]"
        run_both ""
        clean
        ;;
    ii)
        clean; rogue_on
        echo "(ii) impersonate the resolver with a rogue certificate"
        run_both "--resolve resolver.cs6008.local:443:$ATTACKER"
        clean
        ;;
    iii)
        clean; forge_on
        docker exec edge-router sh /scripts/block443.sh >/dev/null
        echo "(iii) deny the encrypted transport (block 443/853)  [Do53 forge ready]"
        run_both ""
        clean
        ;;
    reset) clean; echo "reset done" ;;
    *) echo "usage: $0 {verify|i|ii|iii|reset}"; exit 1 ;;
esac
