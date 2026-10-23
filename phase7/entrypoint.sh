#!/bin/sh
set -e

# Add a route, retrying briefly in case the interface is not configured yet
# (avoids a startup race where eth0 is not ready when this script runs).
add_route() {
    i=0
    while [ $i -lt 10 ]; do
        ip route add "$@" 2>/dev/null && return 0
        i=$((i + 1)); sleep 0.5
    done
    ip route add "$@"
}

# Each node reaches off-subnet addresses only through the router on its segment.
# We drop Docker's default route and install the specific static routes this
# node needs, so no cross-subnet packet can leak past the host instead of our
# routers. The routers themselves just forward (ip_forward is set in compose).

case "$NODE_ROLE" in
    client)
        ip route del default 2>/dev/null || true
        add_route 172.16.2.0/24 via 172.16.1.2
        echo "nameserver 172.16.2.10" > /etc/resolv.conf
        # Install our private CA so curl/kdig trust the resolver's certificate
        # (no insecure -k bypass is needed anywhere).
        if [ -f /etc/bind/ca.crt ]; then
            mkdir -p /usr/local/share/ca-certificates; cp /etc/bind/ca.crt /usr/local/share/ca-certificates/cs6008-ca.crt 2>/dev/null || true
            update-ca-certificates >/dev/null 2>&1 || true
        fi
        ;;

    resolver)
        ip route del default 2>/dev/null || true
        add_route 172.16.3.0/24 via 172.16.2.3
        add_route 172.16.1.0/24 via 172.16.2.2
        ;;

    nameserver)
        ip route del default 2>/dev/null || true
        add_route 172.16.2.0/24 via 172.16.3.3
        ;;

    edge-router|core-router)
        # Dual-homed, forwards between its two subnets. Nothing extra to route.
        ;;

    attacker)
        # On-path adversary on the client subnet (last mile). It does NOT forward in the
        # kernel; all relaying/injection is done by the libpcap interceptor.
        # Leaving ip_forward at its default (0) is what makes the diverted
        # replies reach only the interceptor and not get forwarded twice.
        ;;

    webserver)
        # Same subnet as the client, so no cross-subnet route is needed.
        ;;
esac

exec "$@"
