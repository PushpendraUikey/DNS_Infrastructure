#!/bin/sh
# Run inside core-router.
# Send every reply bound for the resolver through the attacker, which relays
# it on. This is the only change on the router; the resolver and nameservers
# keep their Phase 1 configuration.
ip route replace 172.16.2.10/32 via 172.16.2.100
echo "diversion ON  : replies to 172.16.2.10 now go via 172.16.2.100 (attacker)"
ip route show 172.16.2.10
