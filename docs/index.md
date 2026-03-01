---
sidebar_position: 1
---

# Getting Started with DataService

DataService provides a simple way to manage player data on the server while keeping clients in sync automatically.

## 1) Install

Add DataService to your `wally.toml`:

```toml
[dependencies]
DataService = "leifstout/dataservice@1.0.0"
```

Then run:

```bash
wally install
```

## 2) Define your data template

Create a module for your default player data:

```lua
return {
	currency = 0,
	level = 1,
	xp = 0,
	inventory = {},
	settings = {
		musicVolume = 0.5,
		sfxVolume = 0.5,
	},
}
```

> Keep values JSON-compatible (numbers, strings, booleans, arrays, dictionaries).

## 3) Initialize on the server

In a server script, initialize DataService once:

```lua
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local DataService = require(Packages.DataService).server
local DataTemplate = require(Path.To.DataTemplate)

DataService:init({
	template = DataTemplate,
})
```

## 4) Init, read, and react on the client

Use the client module to read data and subscribe to changes:

```lua
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local DataService = require(Packages.DataService).client

DataService:init()

local currency = DataService:get("currency")
print("Currency:", currency)

DataService:getChangedSignal("currency"):Connect(function(newValue)
	print("Currency updated:", newValue)
end)
```

## 5) Update data on the server

When game logic changes player values, mutate data on the server:

```lua
-- Example: add currency when a player completes a reward
DataService:update(player, "currency", function(current)
	return current + 100
end)
```

```md
# NET API Reference

This page summarises the public API for NET (server + client). For automatic docs generation, annotate your source with docblocks compatible with Moonwave.

---

## Types

### `Stream`
- `Id: number` — stream identifier.
- `Reliable: boolean` — true for ordered, reliable delivery.
- `NextExpected: number` — next expected receive sequence.
- `SendSequence: number` — next sequence number to use for outgoing nodes.
- `SendBuffer: { [number]: BufferedNode }` — reliable nodes pending ACK.
- `ReceiveBuffer: { [number]: Node }` — out-of-order nodes waiting for gaps to fill.

### `Node`
- `StreamId: number`
- `Position: number`
- `AckNumber: number`
- `Reliable: boolean`
- `Nonce: string`
- `Timestamp: number`
- `Token: string`
- `Signature: string`
- `Payload: table`

### `BufferedNode`
- `Node: Node`
- `SentAt: number`
- `Retries: number`

### `Session`
- `Player: Player`
- `Token: string`
- `Secret: string`
- `CreatedAt: number`
- `LastSeen: number`

(Other internal types: `TokenBucket`, `BandwidthSample`, `DeadReckonSample`, `ScriptSignal`)

---

## Public Methods

### `NET:RegisterStream(identifier: number, reliable: boolean)`
Registers a stream on local peer. Must be called on both server and client with the same arguments prior to using the stream.

**Server**: replicates the registration to connected clients.

**Example**
```lua
NET:RegisterStream(1, true)
