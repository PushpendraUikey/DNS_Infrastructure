$TTL 3600
@       IN  SOA ns.com. admin.cs6008. (
                2026102001  ; serial
                3600        ; refresh
                900         ; retry
                604800      ; expire
                3600 )      ; minimum

@       IN  NS  ns.com.
ns.com. IN  A   172.16.3.20

; delegate example.com to domain-ns
example.com.        IN  NS  ns.example.com.
ns.example.com.     IN  A   172.16.3.30
