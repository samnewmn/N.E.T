# NET — Node Exchange Transport

A QUIC-inspired networking module for Roblox, built on top of `RemoteEvent` primitives. NET provides a structured, secure, and multiplexed transport layer with reliable and unreliable stream delivery, session authentication, rate limiting, replay prevention, and more.

## Overview

Rather than managing raw remote events across your codebase, NET exposes a clean stream-based API with built-in security primitives. Both server and client share the same module, with context detected automatically at runtime.

```lua
-- Server
NET:RegisterStream(1, true)
NET:Send(player, 1, { action = "damage", amount = 10 })
NET.OnReceive(1, function(player, data) ... end)

-- Client
NET:RegisterStream(1, true)
NET:Send(1, { x = 0, y = 5, z = 0 })
NET.OnReceive(1, function(data) ... end)
```

## Features

- Multiplexed reliable and unreliable streams
- Session-based authentication with HMAC-style signatures
- Replay prevention via nonce tracking
- Per-player token bucket rate limiting
- Anomaly detection with automatic kick
- Dead reckoning for server-side position validation
- Rolling bandwidth estimation and RTT measurement
- Periodic per-session secret rotation

## Documentation

Full API reference, configuration options, and internal system documentation is available at:

**[View Documentation →](https://samnewmn.github.io/N.E.T)**

## Model Link
**[Click here for Roblox model →](https://create.roblox.com/store/asset/85701138355241/NET)**

## License

This project is provided as-is for use within Roblox projects. See `LICENSE` for details.
