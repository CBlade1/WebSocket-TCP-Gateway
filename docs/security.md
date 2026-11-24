# Security and deployment

A Cloudflare-proxied DNS record and an HTTP WebSocket listener are not sufficient on their own to protect a server. A secure deployment also requires control of origin access and backend ports.

## Origin checklist

1. Set your gateway hostname to **proxied** (orange cloud) in Cloudflare DNS. Ensure WebSockets are allowed for the zone.
2. Use a supported HTTP origin port (`2052`, `2082`, `2086` in the example). These are **ws://**, not encrypted TLS listeners.
3. Restrict inbound traffic to those listeners to Cloudflare's current published IP ranges at the host/cloud firewall. Do this for **IPv4 and IPv6**. Do not assume blocking just one IP family is sufficient.
4. Set `require_cloudflare: true` and populate `trusted_proxies` with Cloudflare's current CIDR ranges. Obtain them from https://www.cloudflare.com/ips/ . Review ranges periodically. The process will reject non-trusted peers when this option is enabled.
5. Set `allowed_hosts` to the public hostname and port combinations clients use (for example, `gateway.example.com:2052`). Do not accept arbitrary Host headers in production.
6. Keep the TCP backend inaccessible from the public Internet. Prefer an actual loopback bind (`127.0.0.1:2828`) rather than `0.0.0.0:2828`; otherwise block the backend's public port at the firewall.
7. Keep application authentication and authorization in your backend. The proxy is not a substitute for them.
8. Configure Cloudflare WAF/rate limits for the WebSocket *upgrade* request, and monitor origin connection pressure. WAF rules do not continuously inspect bytes inside an already upgraded socket.
9. Consider encrypted transport (`wss://`) where possible. Clients requiring `ws://` accept cleartext traffic on the client-to-edge segment. Credentials or sensitive data should not be sent over it.

The application only accepts literal loopback upstream IPs to prevent arbitrary-destination proxying. `CF-Connecting-IP` is ignored unless the direct HTTP peer belongs to `trusted_proxies`.

## Example systemd deployment

Create a dedicated, unprivileged account, copy the binary to `/usr/local/bin/ws-tcp-gateway`, and install `examples/ws-tcp-gateway.service`. Place configuration under `/etc/ws-tcp-gateway/config.json`, owned by root and readable by the service account. Run `systemctl daemon-reload` and `systemctl enable --now ws-tcp-gateway`. Check `journalctl -u ws-tcp-gateway` for startup failures.

The example config has `require_cloudflare` **off** for localhost experimentation. Make the changes above before publishing an address.

## Failure model

- Multi-route legacy session recovery requires compatible client reconnect behavior.
- The gateway cannot protect exposed services on unrelated ports, volumetric attacks against a known origin, or clients that bypass Cloudflare.
- No built-in global bandwidth cap is provided; use OS resource controls, edge limits, and monitoring. Limits on upgraded connections and session queues reduce but cannot remove denial-of-service risk.
- The bridge does not encrypt unencrypted application data.
- Legacy sessions rely on a 32-bit session ID and originating client IP, not a cryptographic per-session token. Do not treat a session ID as authentication. Use only with trusted application protocols and add application-level authorization.
