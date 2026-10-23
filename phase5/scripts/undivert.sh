#!/bin/sh
# Run inside core-router. Remove the diversion and restore direct delivery.
ip route del 172.16.2.10/32 via 172.16.2.100 2>/dev/null || true
echo "diversion OFF : replies to 172.16.2.10 go directly again"
ip route show 172.16.2.10
