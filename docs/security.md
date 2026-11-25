# Deployment and security

The gateway is a transport adapter, not a firewall or application authenticator.

## Network boundary

- Backend targets must be loopback IP addresses. Remote forwarding and caller-selected destinations are not supported.
- Default listeners are loopback-only. For a publicly reachable origin, restrict ingress in the host firewall to known reverse-proxy networks and disable direct access to the backend TCP port.
- `require_trusted_proxy` checks the connecting peer address against `trusted_proxies` and rejects upgrades from other addresses. CIDR lists must be kept current. A local reverse proxy must be explicitly included if used.
- `allowed_hosts` checks the Host header. `allowed_origins` applies to clients that send an Origin header; it is not authentication, and native clients can omit or forge it.
- `/healthz` is only a liveness endpoint and may be publicly accessible if the listener is public.

## Application boundary

The gateway does not authenticate users, understand payloads, or authorize operations. Put authentication in the backend protocol or an upstream proxy where appropriate. Avoid using it to expose a privileged local service to untrusted users.

WebSocket messages are limited by `max_message_bytes`, and simultaneous connections by `max_connections`. Those are process-level safety controls, not distributed denial-of-service defenses. Backends can impose additional per-client limits.

Traffic sent with `ws://` is not encrypted. For sensitive data, terminate TLS at an appropriately configured proxy and use `wss://` externally. If TLS between edge and origin is required, provide it through a separate local reverse proxy or use a Cloudflare-supported encrypted origin configuration.

## Lifecycle

The gateway sends ping frames every 25 seconds and requires pong responses within 90 seconds. On disconnect, the corresponding TCP connection closes. There is no durable session, packet acknowledgement, or transparent reconnect. Applications needing reconnection must provide their own session semantics.

Run as an unprivileged user. Use the included systemd unit as a starting point and review its paths and sandboxing before enabling it.
