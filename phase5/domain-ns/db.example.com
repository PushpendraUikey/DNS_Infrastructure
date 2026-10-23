$TTL 3600
@       IN  SOA ns.example.com. admin.example.com. (
                2026102001  ; serial
                3600        ; refresh
                900         ; retry
                604800      ; expire
                3600 )      ; minimum

@       IN  NS  ns.example.com.
ns      IN  A   172.16.3.30

@       IN  A   172.16.1.20
www     IN  A   172.16.1.20

; internal service hostnames - not advertised anywhere (Phase 5 targets)
dev     IN  A   10.10.0.11
vpn     IN  A   10.10.0.12
mail    IN  A   10.10.0.13
db      IN  A   10.10.0.14
backup  IN  A   10.10.0.15
