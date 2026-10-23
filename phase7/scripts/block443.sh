#!/bin/sh
# Run inside edge-router.
# Deny the encrypted transports (attempt iii): drop the client's DoH/DoT
# connections to the resolver so an opportunistic client is pushed to cleartext.
iptables -I FORWARD -p tcp -d 172.16.2.10 --dport 443 -j DROP
iptables -I FORWARD -p tcp -d 172.16.2.10 --dport 853 -j DROP
echo "blocked TCP 443 (DoH) and 853 (DoT) to the resolver"
