FROM internetsystemsconsortium/bind9:9.20

# Build tools + libpcap so we can compile and run the interceptor.
RUN apk add --no-cache \
        build-base \
        linux-headers \
        libpcap-dev \
        libpcap \
        iproute2 \
        iputils \
        tcpdump

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

COPY attacker/interceptor.c /opt/interceptor.c
RUN gcc -O2 -Wall -Wextra -o /usr/local/bin/interceptor /opt/interceptor.c -lpcap

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
