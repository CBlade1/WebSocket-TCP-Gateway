# WS TCP Gateway

A small WebSocket-to-TCP bridge written in Go. It forwards binary WebSocket messages to a local TCP service and streams the response back over the same connection.

It does not inspect application payloads or require a particular backend protocol. Common use cases include custom TCP APIs, internal services, embedded devices with WebSocket-capable clients, and existing applications that need a WebSocket transport.

## Behavior

- Fixed, named routes to local TCP targets; clients cannot choose a destination.
- Opaque binary forwarding. TCP bytes remain in order, but TCP read boundaries are not WebSocket message boundaries.
- TCP_NODELAY, WebSocket compression off, bounded message size and connection count.
- WebSocket ping/pong and deadline handling.
- Optional ingress restriction to configured reverse-proxy IP ranges.
- A health endpoint at `/healthz`.

A WebSocket client is required. This is not a transparent proxy for unmodified TCP clients. Every WebSocket connection creates a separate backend TCP connection. A disconnected connection is closed on both sides; there is **no session resumption** or replay protocol.

## Build

Go 1.22+ is required.

```sh
go mod download
go build -trimpath -o gateway ./cmd/gateway
cp config.example.json config.json
./gateway -config config.json
```

Example route:

```json
{
  "listen": ["127.0.0.1:2052"],
  "routes": [
    {"name": "service", "path": "/ws/service", "target": "127.0.0.1:2828"}
  ],
  "allowed_hosts": ["localhost:2052"],
  "allowed_origins": [],
  "trusted_proxies": [],
  "require_trusted_proxy": false,
  "max_connections": 2048,
  "max_message_bytes": 1048576
}
```

A server listening on `0.0.0.0:2828` accepts loopback connections to `127.0.0.1:2828`. Keep the backend port private in the host firewall if it should not be reachable directly.

Connect a WebSocket client to `ws://127.0.0.1:2052/ws/service` and send binary messages. Each payload is written to the TCP socket without altering its contents. Backend responses are returned as binary WebSocket messages; their sizes depend on TCP reads.

## Reverse proxies and Cloudflare

For an HTTP-only WebSocket endpoint behind Cloudflare, the edge URL may be `ws://gateway.example.com:2052/ws/service` with a DNS record set to **Proxied**. `ws://` is unencrypted between the client and edge; use `wss://` for confidentiality and integrity. Cloudflare support for particular ports, features, and account plans should be verified before deployment.

The example binds to loopback to avoid exposing an unprotected service. If Cloudflare connects directly to the origin, change `listen` to the relevant interface, configure the firewall to allow only Cloudflare's published IP ranges, set `require_trusted_proxy` to `true`, and populate `trusted_proxies` with current ranges. Do not trust client-supplied forwarding headers from arbitrary peers. Add the expected hostname to `allowed_hosts`.

Cloudflare only proxies the WebSocket HTTP upgrade through its HTTP stack; it is not a generic TCP tunnel for unmodified clients. Its WAF does not inspect all subsequent WebSocket application frames. Floods against an exposed backend port can bypass this gateway entirely.

See [deployment and security notes](docs/security.md).

## Development

```sh
go test -race ./...
go vet ./...
```

CI runs these checks on pull requests. The gateway has not been independently benchmarked; no throughput or failover figures are claimed.

## License

MIT. See [LICENSE](LICENSE).
