#!/bin/sh
# Run inside edge-router. Remove the transport block.
iptables -D FORWARD -p tcp -d 172.16.2.10 --dport 443 -j DROP 2>/dev/null || true
iptables -D FORWARD -p tcp -d 172.16.2.10 --dport 853 -j DROP 2>/dev/null || true
echo "unblocked TCP 443 and 853"
