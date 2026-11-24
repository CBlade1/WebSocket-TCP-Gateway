# ws-tcp-gateway

Small Go gateway for WebSocket clients talking to TCP services on the same host.

A WebSocket endpoint at `ws://gateway.example.com:2052/bridge/app` can forward binary data to `127.0.0.1:2828`. The TCP application does not need to understand HTTP or WebSockets. This works for protocols that can tolerate TCP stream segmentation: WebSocket message boundaries are **not** TCP packet boundaries.

The gateway also includes a compatibility endpoint for the multiplexed OTClient proxy protocol used by the original implementation. That mode is separate from the generic bridge. It keeps backend sessions open across transient WebSocket disconnects and can replay acknowledged packet frames when a compatible client reconnects.

**This is not a universal DDoS shield.** Cloudflare protects proxied HTTP/WebSocket requests when configured correctly. It does not protect a directly exposed TCP backend, and plain TCP clients cannot connect to a WebSocket endpoint without a WebSocket-capable client or adapter. A published origin IP can also still receive attacks on other exposed ports.

## Quick start

Requires Go 1.22 or newer.

```sh
cp config.example.json config.json
go mod tidy
go run ./cmd/gateway -config config.json
```

In the example configuration:

| Endpoint | Destination | Mode |
| --- | --- | --- |
| `ws://gateway.example.com:2052/bridge/app` | `127.0.0.1:2828` | raw binary WebSocket → TCP stream |
| `ws://gateway.example.com:2052/legacy` | destination selected by legacy session frame | multiplexed session protocol |
| `ws://gateway.example.com:2052/` | destination selected by legacy session frame | old-client compatibility |

Equivalent endpoints are available on ports `2082` and `2086`. The configuration can specify additional routes with different paths and TCP backends. All listeners run in the **same Go process on the same server**.

> The default example leaves `require_cloudflare` disabled for local testing. **Do not deploy it publicly like that.** See [Security and deployment](docs/security.md) first.

## What is and isn't universal

**Generic bridge** (`/bridge/app`): any WebSocket-capable application can send and receive binary bytes. TCP writes are forwarded in order. Data read from TCP is sent in binary WebSocket messages. The TCP application does not need special framing. Text WebSocket messages are ignored. On disconnect, the TCP connection is closed. If your application needs resumable sessions, it must implement resumption itself.

**Legacy multiplexed mode** (`/` and `/legacy`): accepts the original 16-bit-length-prefixed multi-session frames (session IDs, sequence IDs, acknowledgments, and destination ports). This mode retains the legacy frame format; it **is not** a generic WebSocket stream. Multiple WebSocket paths/ports share one in-memory session hub. Reconnecting a compatible client with its previous session ID on another port can attach to the existing TCP backend. Unacknowledged outbound frames are replayed. Peer ownership is checked before accepting data and a new client IP cannot take over an existing session ID. A ten-minute orphan timeout bounds the time a backend session remains open without any attached peer.

Continuity is **best effort**, not guaranteed 24/7 transport uptime. Sessions disappear when the process is restarted, after an orphan timeout, or when buffers overflow. The client must reconnect and reattach, with suitable retry/backoff logic. Cross-IP roaming and clustered instances are not supported by the legacy identity model.

## Configure an additional TCP service

Change the route in `config.json` or add another:

```json
{
  "name": "internal-service",
  "path": "/bridge/internal",
  "backend": "127.0.0.1:2828",
  "legacy_port": 2828,
  "proxy_protocol": false
}
```

Route names are for operators; clients connect to the specified path. `legacy_port` maps destination port 2828 from compatible multiplexed client frames to this backend. It is optional for generic routes.

Backends must resolve to a literal IPv4 or IPv6 loopback address. This deliberately prevents the public gateway from becoming an open TCP proxy. **Use `127.0.0.1:2828`, not `0.0.0.0:2828`, as the destination.** Your application may listen on `0.0.0.0:2828`, but connecting to its loopback address avoids exposing that interface unnecessarily. Restrict direct public access to port 2828 using the host firewall.

`proxy_protocol` is disabled by default. Enable it **only** if the backend explicitly supports PROXY protocol v2; otherwise those bytes will corrupt the application's protocol handshake.

## Latency

The gateway uses TCP_NODELAY on local upstream connections, streams binary WebSocket messages without compression, and avoids application-level payload transformations. The generic route does not wait for a fixed-length message before writing bytes to TCP. It does not guarantee a specific latency; measure latency with realistic client workloads and the Cloudflare edge in the path.

## Testing

```sh
go test -race ./...
go vet ./...
go build -trimpath -o gateway ./cmd/gateway
```

CI runs the same checks on pushes and pull requests. See `docs/security.md` for origin access controls and `docs/legacy.md` for session recovery behavior.

## Limitations

- WebSocket clients are required; a native TCP client needs a transport adapter.
- Generic raw mode does not resume an interrupted TCP stream.
- Legacy mode handles bounded in-memory sessions on one process only; no distributed session store.
- Cloudflare's security products inspect the upgrade request, not every application message sent through an upgraded connection.
- HTTP `ws://` is unencrypted on the public client-to-Cloudflare leg. Prefer `wss://` when clients support it. On HTTP origin ports, Cloudflare-to-origin traffic is also unencrypted unless secured separately.
- Trusting `CF-Connecting-IP` is only safe for known Cloudflare proxy peers.

## License

MIT. Third-party dependencies keep their own licenses. Contributions and reproducible bug reports are welcome.
