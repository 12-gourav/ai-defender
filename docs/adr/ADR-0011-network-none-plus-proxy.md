# ADR-0011: `--network none` plus a host-side allowlist proxy over a unix socket

Status: accepted. Date: 2026-10-30.

## Context
Default-deny egress is required, enforced outside the agent's control, protecting against direct-IP bypass, DNS abuse, metadata access and tunnelling. Rootless Docker's user-mode networking offers no convenient host iptables control.

## Decision
Containers run with `--network none`. A host-side Rust proxy listens on a per-session unix socket bind-mounted into the container; a shim stub exposes it on `127.0.0.1:3128` for `HTTP_PROXY`-aware tools. The proxy resolves hostnames itself, checks resolved addresses against deny ranges, enforces host:port allowlists, tunnels CONNECT, logs metadata only, and optionally terminates TLS for specific hosts.

## Consequences
- Tools that ignore proxies, UDP, ICMP, QUIC and plain SSH do not work inside the sandbox by design.
- Localhost services on the host are not reachable without an explicit policy entry and Phase 8 plumbing.
- Allowlisted HTTPS hosts remain a covert channel unless TLS termination is enabled (L3).
