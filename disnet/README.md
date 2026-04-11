# Disnet

Low-level message transport and mesh-routing primitives.

The current tree provides:

- a transport packet type carrying source, target, source sequence number, and payload
- C++20 concepts for validating transport and router implementations
- a flooding router
- a work-in-progress HWMP-style mesh router
- an ESP-NOW transport adapter
