#!/bin/sh
# Run inside edge-router. Remove the diversion and restore direct delivery.
ip route del 172.16.1.10/32 via 172.16.1.100 2>/dev/null || true
echo "diversion OFF : replies to 172.16.1.10 go directly again"
ip route show 172.16.1.10
