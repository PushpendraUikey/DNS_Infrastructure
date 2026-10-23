FROM internetsystemsconsortium/bind9:9.20

# Build tools + libpcap for the interceptor, python3 for the rogue HTTPS server.
RUN apk add --no-cache \
        build-base \
        linux-headers \
        libpcap-dev \
        libpcap \
        iproute2 \
        iputils \
        tcpdump \
        python3

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

COPY attacker/interceptor.c /opt/interceptor.c
RUN gcc -O2 -Wall -Wextra -o /usr/local/bin/interceptor /opt/interceptor.c -lpcap

COPY attacker/rogue_server.py /opt/rogue_server.py

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
