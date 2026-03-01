# NET — Node Exchange Transport
### API Reference & Documentation

> A QUIC-inspired networking module built on top of Roblox's `RemoteEvent` primitives. NET provides multiplexed streams, reliable delivery, authenticity checking, rate limiting, replay prevention, session management, dead reckoning, and bandwidth estimation.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [Core Concepts](#core-concepts)
   - [Streams](#streams)
   - [Nodes](#nodes)
   - [Sessions](#sessions)
   - [Security Pipeline](#security-pipeline)
6. [Public API](#public-api)
   - [RegisterStream](#registerstream)
   - [Send](#send)
   - [OnReceive](#onreceive)
   - [GetRTT](#getrtt)
   - [GetBandwidth](#getbandwidth)
   - [IsSuspiciousPosition](#issuspiciousposition)
   - [GetSession](#getsession)
   - [GetStream](#getstream)
7. [Type Definitions](#type-definitions)
8. [Internal Systems](#internal-systems)
   - [Handshake & Session Lifecycle](#handshake--session-lifecycle)
   - [Reliable Delivery & Retransmission](#reliable-delivery--retransmission)
   - [Rate Limiting (Token Bucket)](#rate-limiting-token-bucket)
   - [Anomaly Detection](#anomaly-detection)
   - [Replay Prevention](#replay-prevention)
   - [Signature Verification](#signature-verification)
   - [Dead Reckoning](#dead-reckoning)
   - [Bandwidth Estimation](#bandwidth-estimation)
   - [RTT Measurement](#rtt-measurement)
   - [Secret Rotation](#secret-rotation)
9. [System Messages](#system-messages)
10. [Limitations & Known Caveats](#limitations--known-caveats)

---

## Overview

NET abstracts Roblox's `RemoteEvent` and `UnreliableRemoteEvent` primitives into a structured, secure, and multiplexed transport layer. Instead of raw remote events scattered across your codebase, NET gives you typed **streams**, each with independent sequencing, buffering, and delivery guarantees.

**Key features at a glance:**

| Feature | Description |
|---|---|
| Multiplexed streams | Multiple independent logical channels over shared remotes |
| Reliable delivery | TCP-like sequenced delivery with ACKs and retransmission |
| Unreliable delivery | UDP-like fire-and-forget for latency-sensitive data |
| Session authentication | Token + HMAC-style signature on every packet |
| Replay prevention | Nonce tracking with configurable expiry window |
| Rate limiting | Per-player token bucket with per-stream configurable cost |
| Anomaly detection | Packets-per-second tracking with auto-kick on sustained abuse |
| Dead reckoning | Server-side position validation against predicted movement |
| Bandwidth estimation | Rolling per-player outgoing bytes-per-second counter |
| RTT measurement | Periodic server-to-client ping/pong with latency tracking |
| Secret rotation | Periodic per-session secret refresh to limit replay windows |

---

## Architecture

```
Client                              Server
  |                                   |
  |--- UnreliableRemote (node) ------>|
  |--- ReliableRemote   (node) ------>|
  |                                   |-- StreamManager:Receive()
  |                                   |-- Pipeline:
  |                                   |     Validate Session Token
  |                                   |     → Replay Check (nonce + timestamp)
  |                                   |     → Stream Existence Check
  |                                   |     → Sequence Window Check
  |                                   |     → Signature Verification (HMAC)
  |                                   |     → Rate Limit (token bucket)
  |                                   |     → Anomaly Detection
  |                                   |     → Process / Buffer / Deliver
  |<-- AckRemote        (ack)  -------|
  |<-- ReliableRemote   (node) -------|
```

**Remote instances** (created automatically under `CONFIG.FolderParent`):

| Name | Type | Purpose |
|---|---|---|
| `____Request` | `RemoteFunction` | Initial handshake (token + secret exchange) |
| `____Event` | `RemoteEvent` | Reliable channel — batched node arrays |
| `____Unreliable` | `UnreliableRemoteEvent` | Unreliable channel — batched node arrays |
| `____Ack` | `RemoteEvent` | Acknowledgement channel |

---

## Quick Start

### Server

```lua
local NET = require(path.to.NET)

-- Register streams (must match client)
NET:RegisterStream(1, true)   -- Stream 1: reliable
NET:RegisterStream(2, false)  -- Stream 2: unreliable

-- Listen for incoming data
NET.OnReceive(1, function(player, data)
    print(player.Name, data.action, data.amount)
end)

-- Send data to a player
NET:Send(player, 1, { action = "damage", amount = 10 })
```

### Client

```lua
local NET = require(path.to.NET)

-- Register streams (must match server)
NET:RegisterStream(1, true)
NET:RegisterStream(2, false)

-- Listen for incoming data
NET.OnReceive(1, function(data)
    print(data.action, data.amount)
end)

-- Send data to server
NET:Send(1, { x = 0, y = 5, z = 0 })
```

> **Important:** `RegisterStream` must be called with matching arguments on both server and client before any nodes are sent or received on that stream. Streams registered on the server before a client connects are automatically replicated to the client during handshake. Streams registered after a client connects are pushed via `STREAM_REGISTER` system messages.

---

## Configuration

All tunable parameters live in the `CONFIG` table at the top of the module. Edit these to suit your game's needs.

| Key | Default | Description |
|---|---|---|
| `FolderParent` | `script` | Parent instance for the `NetworkInstances` folder |
| `NameDictionary.Folder` | `"NetworkInstances"` | Name of the container folder |
| `NameDictionary.Request` | `"____Request"` | Name of the handshake `RemoteFunction` |
| `NameDictionary.UnreliableEvent` | `"____Unreliable"` | Name of the unreliable remote |
| `NameDictionary.Reliable` | `"____Event"` | Name of the reliable remote |
| `NameDictionary.Ack` | `"____Ack"` | Name of the ACK remote |
| `VerboseDebug` | `false` | Enable detailed logging via `print` |
| `Timeout` | `10` | Seconds before `WaitForChild` gives up on the client |
| `NonceLength` | `6` | Character length of generated nonces |
| `NonceExpiry` | `10` | Seconds before a seen nonce is purged from memory |
| `StreamWindow` | `64` | Sequence numbers outside `±64` of `NextExpected` are rejected |
| `RetransmitInterval` | `0.2` | Seconds between retransmit attempts for unacknowledged reliable nodes |
| `MaxRetries` | `8` | Retransmit attempts before a buffered node is dropped |
| `SessionExpiry` | `3600` | Seconds before a session token is considered stale |
| `SecretRotation` | `30` | Seconds between per-session secret rotations |
| `BucketCapacity` | `100` | Max burst tokens per player |
| `BucketRefillRate` | `20` | Tokens restored per second per player |
| `StreamCosts` | `{}` | Map of `streamId → tokenCost`; defaults to `1` if not listed |
| `PositionThreshold` | `20` | Studs — dead reckoning deviation threshold |
| `BandwidthWindow` | `1` | Seconds per bandwidth measurement window |
| `PacketsPerSecondLimit` | `60` | Packets/sec above which an anomaly is flagged |
| `MaxViolations` | `5` | Sustained violations before the player is kicked |

---

## Core Concepts

### Streams

A **stream** is a logical channel identified by a numeric ID. Each stream maintains its own independent sequence counter, send buffer, and receive buffer. Streams can be either **reliable** or **unreliable**.

- **Reliable streams** guarantee ordered, exactly-once delivery via sequence numbers, ACKs, and retransmission. Analogous to TCP.
- **Unreliable streams** fire-and-forget with no ordering guarantee. Analogous to UDP. Use these for high-frequency data where losing a frame is acceptable (e.g. position updates).

### Nodes

A **node** is the fundamental unit of data transmitted over a stream. Every call to `NET:Send()` builds a node, signs it, and places it into the outgoing queue. Nodes carry:

- Stream and sequence metadata (`StreamId`, `Position`, `AckNumber`)
- Security fields (`Token`, `Nonce`, `Timestamp`, `Signature`)
- An arbitrary `Payload` table

On the server, nodes are **batched** per-player and flushed each `Heartbeat` to minimise remote event calls. Another name for a node is a packet, which is used in general computer science terms as what is transmitted between contexts.

### Sessions

Each player receives a unique **session** upon their first handshake with the server. The session holds a `Token` (used to authenticate every node) and a `Secret` (used as the HMAC key for signature verification). Sessions expire after `CONFIG.SessionExpiry` seconds of total lifetime.

### Security Pipeline

Every node received from a client passes through a sequential validation pipeline before being delivered to application code:

```
1. Session token validity    — Is the token known and unexpired?
2. Replay check              — Has this nonce been seen, or is the timestamp too old?
3. Stream existence          — Does the target stream exist?
4. Sequence window check     — Is the sequence number within the sliding window?
5. Signature verification    — Does the HMAC match, given the session secret?
6. Rate limiting             — Does the player have enough tokens in their bucket?
7. Anomaly detection         — Is the packet rate suspiciously high?
```

A node that fails any step is silently dropped and logged (if `VerboseDebug` is enabled).

---

## Public API

### `RegisterStream`

```lua
NET:RegisterStream(identifier: number, reliable: boolean)
```

Registers a new stream on this peer. Must be called on **both server and client** with matching arguments.

| Parameter | Type | Description |
|---|---|---|
| `identifier` | `number` | Unique stream ID |
| `reliable` | `boolean` | `true` for reliable (TCP-like), `false` for unreliable (UDP-like) |

Calling `RegisterStream` on a stream ID that is already registered is a no-op (logs a warning if `VerboseDebug` is enabled).

When called on the **server**, the new stream is automatically replicated to all currently connected clients via a `STREAM_REGISTER` system message.

**Example:**
```lua
NET:RegisterStream(1, true)   -- reliable
NET:RegisterStream(2, false)  -- unreliable
NET:RegisterStream(10, true)  -- another reliable stream
```

### `UnregisterStream`

```lua
NET:UnregisterStream(identifier: number)
```

Unregisters a stream, removing it from both the stream table and the receive-signal table. Any buffered nodes for this stream are discarded. On the server, all connected clients are notified so they unregister their local copy too.

**Example:**
```lua
NET:UnregisterStream(1)   -- Unregisters stream 1
NET:UnregisterStream(2)  -- Unregisters stream 2
NET:UnregisterStream(10)  -- Unregisters stream 10
```

---

### `Send`

```lua
-- Server
NET:Send(player: Player, streamId: number, payload: table)

-- Client
NET:Send(streamId: number, payload: table)
```

Constructs a node, signs it with the current session secret, and enqueues it for delivery.

**Server parameters:**

| Parameter | Type | Description |
|---|---|---|
| `player` | `Player` | The recipient |
| `streamId` | `number` | Target stream ID |
| `payload` | `table` | Arbitrary data to deliver |

**Client parameters:**

| Parameter | Type | Description |
|---|---|---|
| `streamId` | `number` | Target stream ID |
| `payload` | `table` | Arbitrary data to deliver |

On the **server**, nodes are batched per-player and flushed on `Heartbeat`. On the **client**, nodes are sent immediately.

**Example:**
```lua
-- Server
NET:Send(player, 1, { action = "heal", amount = 25 })

-- Client
NET:Send(2, { position = Vector3.new(10, 0, 5), velocity = Vector3.new(1, 0, 0) })
```

---

### `OnReceive`

```lua
NET.OnReceive(streamId: number, callback: (...any) -> ()): ScriptConnection
```

Registers a callback to fire when a node is received on the given stream. This is a **static function** (called with `.`, not `:`).

The stream **must be registered** before calling `OnReceive`.

**Server callback signature:** `function(player: Player, data: table)`  
**Client callback signature:** `function(data: table)`

| Parameter | Type | Description |
|---|---|---|
| `streamId` | `number` | Stream to listen on |
| `callback` | `function` | Called for each received node payload |

**Returns:** `ScriptConnection` — call `:Disconnect()` to unsubscribe.

**Example:**
```lua
-- Server
local conn = NET.OnReceive(1, function(player, data)
    print(player.Name .. " sent:", data.action)
end)

-- Client
NET.OnReceive(1, function(data)
    print("Received:", data.action)
end)

-- Unsubscribe later
conn:Disconnect()
```

---

### `GetRTT`

```lua
NET:GetRTT(player: Player): number?
```

Returns the most recently measured round-trip time for a player, in **seconds**. Returns `nil` if no RTT measurement has been taken yet.

**Server only.**

```lua
local rtt = NET:GetRTT(player)
if rtt then
    print(string.format("Ping: %dms", math.floor(rtt * 1000)))
end
```

RTT is measured automatically via a server-initiated ping/pong loop every 5 seconds.

---

### `GetBandwidth`

```lua
NET:GetBandwidth(player: Player): number
```

Returns the estimated outgoing bandwidth to a player in **bytes per second**. Returns `0` if no data has been sent yet.

**Server only.**

```lua
local bps = NET:GetBandwidth(player)
print(string.format("Bandwidth to %s: %d B/s", player.Name, bps))
```

The estimate is based on a rolling window of `CONFIG.BandwidthWindow` seconds.

---

### `IsSuspiciousPosition`

```lua
NET:IsSuspiciousPosition(player: Player, position: Vector3, velocity: Vector3): boolean
```

Validates a client-reported movement position using **dead reckoning**. Returns `true` if the reported position deviates from the server's prediction by more than `CONFIG.PositionThreshold` studs.

**Server only.**

| Parameter | Type | Description |
|---|---|---|
| `player` | `Player` | The player to validate |
| `position` | `Vector3` | Client-reported position |
| `velocity` | `Vector3` | Client-reported velocity (used to update the internal model) |

On the **first call** for a player, the position is accepted and stored as the baseline; `false` is always returned.

```lua
NET.OnReceive(2, function(player, data)
    if NET:IsSuspiciousPosition(player, data.position, data.velocity) then
        warn(player.Name .. " may be speed-hacking!")
    end
end)
```

---

### `GetSession`

```lua
NET:GetSession(player: Player): Session?
```

Returns the active `Session` for a player, or `nil` if no session exists (e.g. the player hasn't completed the handshake yet, or has left).

**Server only.**

```lua
local session = NET:GetSession(player)
if session then
    print("Token:", session.Token)
    print("Age:", tick() - session.CreatedAt, "seconds")
end
```

---

### `GetStream`

```lua
NET:GetStream(streamId: number): Stream?
```

Returns the `Stream` table for a given stream ID, or `nil` if not registered. Available on both server and client.

```lua
local stream = NET:GetStream(1)
if stream then
    print("Next expected sequence:", stream.NextExpected)
    print("Send sequence:", stream.SendSequence)
end
```

## Core Public ScriptSignals

### `OnStateCleanup`

```lua
NET.OnStateCleanup:Connect(function(cleaningUpPlayer: Player)
```

Runs whenever a player's state is being cleaned up internally.

### `OnAnomalyDetected`

```lua
NET.OnAnomalyDetected:Connect(function(playerWhichIsDetected: Player, message: string)
```

Runs whenever a player fails to pass anomaly tests, could be seen as an intruder.

### `OnCriticalAnomalyDetected`

```lua
NET.OnCriticalAnomalyDetected:Connect(function(playerWhichIsDetected: Player, message: string)
```

Runs whenever a critical anomaly is detected, and needs urgent action (such as kicking the player on this signal being fired).

### `OnInvalidSequence`

```lua
NET.OnInvalidSequence:Connect(function(stream: Stream, sequenceNumber: number)
```

Whenever an invalid sequence is detected, which is too far from the given window that is given in CONFIG.

### `OnRateLimit`

```lua
NET.OnRateLimit:Connect(function(player: Player)
```

Runs whenever a player is rate limited.

### `OnUnacknowledgedNode`

```lua
NET.OnUnacknowledgedNode:Connect(function(streamId: number, sequence: number, bufferedNode: BufferedNode)
```

Runs whenever a reliable node is unacknowledged, which signifies that the opposing context isnt recieving network invokations.

### `OnInvalidNodeFromClient`

```lua
NET.OnInvalidNodeFromClient:Connect(function(player: Player, node: Node)
```

Runs whenever a client sends an invalid node back to the server.

### `OnInvalidSession`

```lua
NET.OnInvalidSession:Connect(function(player: Player, nodeToken: string)
```

Runs whenever an invalid session is detected (expired session or invalid token).

### `OnInvalidSignature`

```lua
NET.OnInvalidSignature:Connect(function(player: Player, node: Node)
```

Runs whenever an invalid signature is detected from a client, with the given Node.

### `OnNodeProcessed`

```lua
NET.OnNodeProcessed:Connect(function(node: Node, player: Player?)
```

Runs whenever an ynode is processed internally

---

## Type Definitions

### `Stream`

```lua
export type Stream = {
    Id:            number,
    Reliable:      boolean,
    NextExpected:  number,            -- Next sequence number expected to arrive
    SendSequence:  number,            -- Last sequence number sent
    SendBuffer:    { [number]: BufferedNode },   -- Unacknowledged reliable nodes
    ReceiveBuffer: { [number]: Node },           -- Out-of-order nodes awaiting gap fill
}
```

### `Node`

```lua
export type Node = {
    StreamId:  number,           -- Stream this node belongs to
    Position:  number,           -- Sequence number within the stream
    AckNumber: number,           -- Last sequence number confirmed received from sender
    Reliable:  boolean,          -- Whether this node expects an ACK
    Nonce:     string,           -- Unique nonce for replay prevention
    Timestamp: number,           -- tick() at send time
    Token:     string,           -- Session token for authenticity
    Signature: string,           -- HMAC-style signature of the serialised payload
    Payload:   { [any]: any },   -- Application data
}
```

### `Session`

```lua
export type Session = {
    Player:    Player,
    Token:     string,    -- Issued at handshake; included in every node
    Secret:    string,    -- HMAC key; rotated every CONFIG.SecretRotation seconds
    CreatedAt: number,    -- tick() at session creation
    LastSeen:  number,    -- tick() of the most recently validated node
}
```

### `TokenBucket`

```lua
export type TokenBucket = {
    Tokens:     number,    -- Current available tokens
    LastRefill: number,    -- tick() of the last refill calculation
}
```

### `BandwidthSample`

```lua
export type BandwidthSample = {
    BytesThisWindow: number,    -- Bytes sent in the current window
    WindowStart:     number,    -- tick() when the current window started
    EstimatedBps:    number,    -- Bytes/sec measured in the previous window
}
```

### `DeadReckonSample`

```lua
export type DeadReckonSample = {
    LastPosition:  Vector3,
    LastVelocity:  Vector3,
    LastTimestamp: number,    -- tick() of the last sample
}
```

### `ScriptConnection`

```lua
export type ScriptConnection = {
    Connected:  boolean,
    Disconnect: (self: ScriptConnection) -> (),
}
```

### `ScriptSignal`

```lua
export type ScriptSignal = {
    Connect: (self: ScriptSignal, (...any) -> ()) -> ScriptConnection,
    Fire:    (self: ScriptSignal, ...any) -> (),
}
```

---

## Internal Systems

### Handshake & Session Lifecycle

When a client loads the module, it immediately invokes `HandshakeRemote:InvokeServer()`. The server:

1. Generates a unique `Token` (two concatenated nonces) and a `Secret` (a hex-encoded random value).
2. Stores the session in `NET.Sessions[player]`.
3. Returns the token, secret, and a list of all currently registered streams to the client.

The client stores the token and secret locally, registers the replicated streams, then fires a `READY` message back to the server to signal that all listeners are connected. The server sets `NET.ReadyPlayers[player] = true` upon receiving this signal, which is a prerequisite for the outgoing batch queue to flush to that player.

On player disconnect, all per-player state (session, bucket, anomaly stats, bandwidth, dead reckoning, outgoing queue, RTT) is cleaned up immediately.

---

### Reliable Delivery & Retransmission

Reliable streams implement a sliding-window protocol:

- **Sender:** Each node is assigned an incrementing `Position`. After sending, the node is stored in `stream.SendBuffer[position]`.
- **Receiver:** On receipt, if the node's `Position == NextExpected + 1`, it is delivered immediately and `NextExpected` is advanced. Nodes that arrive out of order are stored in `stream.ReceiveBuffer` until the gap is filled.
- **ACK:** The receiver sends an ACK (`{ StreamId, AckPosition }`) for every reliable node it accepts. The sender removes the corresponding entry from `SendBuffer` on receipt.
- **Retransmission:** A `Heartbeat` loop checks `SendBuffer` every frame. Nodes that haven't been acknowledged within `CONFIG.RetransmitInterval` seconds are resent. After `CONFIG.MaxRetries` failed attempts, the node is dropped and a warning is logged.

---

### Rate Limiting (Token Bucket)

Each player has a token bucket with capacity `CONFIG.BucketCapacity` and a refill rate of `CONFIG.BucketRefillRate` tokens per second. Each incoming node consumes tokens equal to `CONFIG.StreamCosts[streamId]` (defaulting to `1`).

If a player's bucket is empty when a node arrives, the node is **silently dropped**. Tokens are refilled lazily on each incoming packet.

To assign a higher cost to a specific stream:
```lua
CONFIG.StreamCosts[5] = 10  -- Stream 5 costs 10 tokens per packet
```

---

### Anomaly Detection

The server tracks the number of packets received per second per player. At the end of each 1-second window:

- If `count > CONFIG.PacketsPerSecondLimit`, a **violation** is recorded and logged.
- If `violations >= CONFIG.MaxViolations`, the player is kicked with the message `"[NET] Suspicious network activity detected."`.

The per-second counter and violation count are stored in `NET.AnomalyStats[player]`.

---

### Replay Prevention

Every node carries a `Nonce` (a short random string) and a `Timestamp` (`tick()` at send time). On the server:

1. If `node.Nonce` has been seen before → **reject** (replay).
2. If `|tick() - node.Timestamp| > CONFIG.NonceExpiry` → **reject** (stale / clock-skewed).
3. Otherwise, record `NET.SeenNonces[nonce] = tick()`.

A background task purges nonces older than `CONFIG.NonceExpiry` seconds every `CONFIG.NonceExpiry` seconds to prevent unbounded memory growth.

---

### Signature Verification

Each node is signed using a lightweight XOR-based MAC:

```
Signature = Sign(Encode(node_without_signature), session.Secret)
```

`Encode()` produces a deterministic, sorted key=value string from the node's fields. `Sign()` iterates over the encoded bytes, XORing each against the corresponding secret byte (with wrapping) and accumulating via bitwise rotation, producing an 8-character hex digest.

On the server, the incoming node's signature field is stripped, the expected signature is recomputed, and both are compared. Nodes with mismatched signatures are dropped.

> **Note:** This is not a cryptographically strong MAC. It provides integrity and basic authenticity against unsophisticated tampering, but should not be considered resistant to determined adversaries.

---

### Dead Reckoning

`IsSuspiciousPosition` maintains a per-player `DeadReckonSample` containing the last known position, velocity, and timestamp. On each call:

1. The **predicted** position is computed as `LastPosition + LastVelocity * dt`.
2. The deviation between the predicted and reported positions is measured.
3. If deviation exceeds `CONFIG.PositionThreshold` studs, the method returns `true`.
4. The sample is updated with the new reported values regardless of the result.

This is a building block — NET does not automatically kick players for suspicious positions. Your code decides the response.

---

### Bandwidth Estimation

`trackBandwidth(player, bytes)` is called internally every time a node is enqueued for sending to a player. It accumulates outgoing bytes within a `CONFIG.BandwidthWindow`-second rolling window, then updates `EstimatedBps` at the end of each window.

`GetBandwidth(player)` returns the `EstimatedBps` from the **previous** completed window.

---

### RTT Measurement

Every 5 seconds, the server sends a `PING` system message to each connected player. The client responds immediately with a `PONG`. When the server receives the pong:

```lua
NET.RTT[player] = tick() - NET.PingTimestamps[player]
```

`GetRTT(player)` returns this value in seconds. Multiply by 1000 for milliseconds.

---

### Secret Rotation

Every `CONFIG.SecretRotation` seconds (default: 30), the server generates a new `Secret` for each connected player and pushes it via a `SECRET_ROTATION` system message on the reliable channel. The client updates its local `NET.ClientSecret` immediately upon receipt.

Rotating the secret limits the window during which a captured secret could be exploited. All nodes sent after the rotation use the new secret.

---

## System Messages

NET uses reserved stream ID `-1` for internal control messages. These are processed before reaching application code and are never delivered to `OnReceive` handlers. You should not use stream ID `-1` for application streams.

| `Payload.__type` | Direction | Description |
|---|---|---|
| `"READY"` | Client → Server | Signals that the client has registered all replicated streams and is ready to receive |
| `"PING"` | Server → Client | RTT probe; client responds with `PONG` |
| `"PONG"` | Client → Server | RTT response |
| `"SECRET_ROTATION"` | Server → Client | Carries a new `secret` field to replace the client's session secret |
| `"STREAM_REGISTER"` | Server → Client | Registers a new stream on the client; carries `id` and `reliable` fields |

---

## Limitations & Known Caveats

**Signature strength.** The XOR-based HMAC is not secure enough. It will catch accidental corruption and low-effort tampering, but a motivated attacker with knowledge of the algorithm could potentially forge signatures. For high-stakes validation, consider augmenting with server-side authoritative game logic.

**Single-module design.** NET requires the same module instance to be required by both server and client scripts. It auto-detects its context via `RunService:IsServer()`.

**Stream registration order.** If you call `OnReceive` before `RegisterStream`, an assertion error will be thrown. Always register your streams first.

**Sequence numbers are not validated on the client.** Nodes received from the server are delivered without the full security pipeline that applies to client→server traffic. This is by design — the server is trusted.
