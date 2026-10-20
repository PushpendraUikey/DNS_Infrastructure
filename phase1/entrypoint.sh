#!/bin/sh
set -e

# Each node reaches off-subnet addresses only through the router on its segment.
# We drop Docker's default route and install the specific static routes this
# node needs, so no cross-subnet packet can leak past the host instead of our
# routers. The routers themselves just forward (ip_forward is set in compose).

case "$NODE_ROLE" in
    client)
        ip route del default 2>/dev/null || true
        ip route add 172.16.2.0/24 via 172.16.1.2
        echo "nameserver 172.16.2.10" > /etc/resolv.conf
        ;;

    resolver)
        ip route del default 2>/dev/null || true
        ip route add 172.16.3.0/24 via 172.16.2.3
        ip route add 172.16.1.0/24 via 172.16.2.2
        ;;

    nameserver)
        ip route del default 2>/dev/null || true
        ip route add 172.16.2.0/24 via 172.16.3.3
        ;;

    edge-router|core-router)
        # Dual-homed, forwards between its two subnets. Nothing extra to route.
        ;;

    webserver)
        # Same subnet as the client, so no cross-subnet route is needed.
        ;;
esac

exec "$@"
