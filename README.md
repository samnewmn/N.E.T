# NET — Node Exchange Transport

A QUIC-inspired networking module built on top of Roblox Remote events.
Provides multiplexed streams, reliable delivery, replay prevention, session management,
dead reckoning, bandwidth estimation, rate limiting, and other features.

This repo contains:
- `src/` — the Luau ModuleScript(s) (NET).
- `docs/` — hand-written docs (API summary) and Moonwave output (if you generate it).
- `.moonwave.toml` — Moonwave config.
- `.selene.toml` — Selene config.
- `.github/workflows/` — CI & docs workflows.

## Goals
- Strong runtime guarantees for multiplayer messaging (reliability, ordering when needed).
- Simple API for client and server usage.
- Good observability (RTT, bandwidth, anomaly detection).
- Tooling-friendly: linters, type checks, and generated API docs (Moonwave).

## Quick install (development)
1. Add this repository to your project (submodule, copy `src/NET.lua`, or use Rojo).
2. Run format/lint tools locally (recommended):
   ```sh
   # install tools (examples)
   npm i -g moonwave         # docs generator
   cargo install selene      # linter
   npm i -g stylua           # optional formatter (or use prebuilt)
