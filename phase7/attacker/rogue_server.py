#!/usr/bin/env python3
# Rogue HTTPS endpoint used in attempt (ii). It presents a certificate for
# resolver.cs6008.local that is NOT signed by the lab CA (self-signed), so a
# client that validates the certificate will refuse the connection before any
# DNS answer is exchanged.
import http.server
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/certs/rogue.crt", "/certs/rogue.key")

httpd = http.server.HTTPServer(("0.0.0.0", 443), http.server.BaseHTTPRequestHandler)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print("[rogue] HTTPS server up on 443 with an untrusted certificate")
httpd.serve_forever()
