# Disnet

Low-level message transport and mesh-routing primitives.

The current tree provides:

- a transport packet type carrying source, target, source sequence number, and payload
- C++20 concepts for validating transport and router implementations
- a flooding router with TTL and duplicate suppression
- an HWMP-style mesh router with:
  - reactive route discovery (PREQ/PREP)
  - optional proactive/root announcements
  - route invalidation and PERR propagation
  - pending packet queuing while routes are being discovered
- an ESP-NOW transport adapter

## Test status

Host-side tests live under `disnet/test` and currently cover:

- HWMP frame protocol encoding/handling
- route lifecycle behavior
- error and duplicate handling
- reactive and root behavior in `schwi` simulations
- ESP-NOW and HWMP regression checks
