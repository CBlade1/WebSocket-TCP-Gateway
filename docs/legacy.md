# Legacy multi-route session protocol

The compatibility endpoint was retained from the supplied production gateway, rather than being reimplemented as a generic TCP tunnel.

It accepts framed binary traffic with session ID, packet ID, last-acknowledged packet ID, and application destination port. Peer connections can attach to the same backend session over multiple configured WebSocket listeners. TCP-to-client packets are queued until acknowledged. Duplicate or out-of-order client frames are tracked by sequence ID and delivered in order to the backend.

A WebSocket close (including code 1001, 'going away') detaches the affected peer. It does not immediately terminate its TCP sessions. Another compatible peer can reattach and receive pending frames. Sessions are removed if all peers remain absent for ten minutes, the TCP backend closes, or buffered traffic exceeds configured limits.

Cloudflare sometimes terminates WebSocket connections during edge maintenance or idle transitions. The application **cannot stop** Cloudflare from doing so. The client must reconnect, reattach its session IDs and retransmit any unacknowledged client-to-server frames. The Go process must remain running and retain session state. This feature cannot restore state after the gateway process is restarted.

The legacy wire format is application-specific. It should not be advertised as generic WebSocket traffic. For arbitrary TCP applications use `/bridge/<route>`.

## Compatibility details

- By default the root `/` path and `/legacy` expose the same legacy hub on each configured listener.
- One destination `legacy_port` maps to one configured local TCP backend.
- PROXY v2 headers are opt-in. Enable them only on backends that parse them.
- The gateway rejects frames sent for sessions a peer has not registered.
- A reattach must use the same IP string and destination as the original session. This is legacy compatibility behavior, **not** strong authentication.
- Reconnects on another instance, client IP changes, session ID rollover, or sustained disconnection cannot be made transparent by this gateway alone.
