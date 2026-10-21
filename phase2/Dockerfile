FROM internetsystemsconsortium/bind9:9.20

# Base image is Alpine and already ships named, dig, delv and ip.
# Add the few extra tools the lab needs on top of that.
RUN apk add --no-cache \
        curl \
        python3 \
        tcpdump \
        iproute2 \
        iputils \
        procps

# named needs its working directory writable to create its session key etc.
RUN chmod 0777 /var/cache/bind

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
