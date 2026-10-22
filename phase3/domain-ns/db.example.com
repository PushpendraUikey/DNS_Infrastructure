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
