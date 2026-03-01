--[[
	NET - Node Exchange Transport v1.0.2
	
	A QUIC-inspired networking module built on top of Roblox's RemoteEvent primitives.
	Provides multiplexed streams, reliable delivery, authenticity checking, rate limiting,
	replay prevention, session management, dead reckoning, and bandwidth estimation.

	Changes in v1.0.2:
	  - Fixed server retransmission: SendBuffers is now per-player rather than per-stream,
	    so the retransmit loop knows which player to FireClient to.
	  - Secret rotation messages are now signed with the OLD secret and verified by the client,
	    so a malicious actor cannot spoof a rotation to downgrade a client's secret.
	  - Handshake is now rate-limited per-player via HandshakeCooldown; repeated invocations
	    within the cooldown window return nil and are logged.
	  - trackBandwidth is now called on the client side too (upload direction) via
	    trackClientBandwidth; exposed publicly as NET:GetClientBandwidth().
	  - Added NET:UnregisterStream(id) — removes a stream at runtime and notifies clients.
	  - Added NET:ResetDeadReckon(player) — clears the dead-reckoning sample so legitimate
	    teleports/respawns don't produce false positives.
	  - DeadReckon state is explicitly cleared in PlayerRemoving cleanup.
	
	This basically utilises UnreliableRemoteEvents in order to use a QUIC-like protocol for 
	creating a custom networking module.

	NET is designed for both data transmittion protocols such as UDP and TCP
	here is a link which could help you understand these protocols:
	https://www.geeksforgeeks.org/computer-networks/differences-between-tcp-and-udp/

	We use streams which commuicates Nodes across networks, with authentication and protocols
	which help ensure that the stream, if reliable, will not be lost (AKA packet loss).

	We utilise a form of UDP (UnreliableRemoteEvents) to send Nodes through unreliable streams,
	which could be used for things that do not require Asynchronous events, and is more
	performant than RemoteEvents, such as movement systems, where if a Node is lost the next
	Node is most likely already there and therefore doesnt need reliable communication.

	On the other hand TCP (RemoteEvents) is a reliable form of communication, used for things
	that require reliable communication, like logging certain actions, sending data to the
	server, etc. We tend to use TCP for most things that requires Asynchronous events,
	such as DataStores.

	On top of all this, we have security and profiling methods to ensure that only the client
	and server can send and receive data, and that bandwidth is estimated and limited per player.
	
	GitHub: 

	Usage (Server):
		local NET = require(path.to.NET)
		NET:RegisterStream(1, true)   -- reliable stream
		NET:RegisterStream(2, false)  -- unreliable stream
		NET:Send(player, 1, { action = "damage", amount = 10 })
		NET.OnReceive(1, function(player, data) ... end)

	Usage (Client):
		local NET = require(path.to.NET)
		NET:Send(1, { x = 0, y = 5, z = 0 })
		NET.OnReceive(1, function(data) ... end)
]]

export type Stream = {
	Id: number,
	Reliable: boolean,
	NextExpected: number,
	SendSequence: number,
	SendBuffer: { [number]: BufferedNode },   -- Unacknowledged reliable nodes (CLIENT only)
	ReceiveBuffer: { [number]: Node },         -- Out-of-order nodes awaiting gap fill
}

export type Node = {
	StreamId: number,        -- Stream this node belongs to
	Position: number,        -- Position of this node in the stream (sequence number)
	AckNumber: number,       -- Last position we have confirmed receiving from sender
	Reliable: boolean,       -- Whether this node expects acknowledgment
	Nonce: string,           -- Unique nonce for replay prevention
	Timestamp: number,       -- tick() at send time, used for expiry checks
	Token: string,           -- Session token for authenticity
	Signature: string,       -- HMAC-style signature of the serialised payload
	Payload: { [any]: any }, -- Arbitrary data payload
}

-- Internal only — wraps a Node with retransmission metadata
type BufferedNode = {
	Node: Node,
	SentAt: number,
	Retries: number,
}

export type Session = {
	Player: Player,
	Token: string,
	Secret: string,
	CreatedAt: number,
	LastSeen: number,
}

export type TokenBucket = {
	Tokens: number,
	LastRefill: number,
}

export type BandwidthSample = {
	BytesThisWindow: number,
	WindowStart: number,
	EstimatedBps: number,
}

export type DeadReckonSample = {
	LastPosition: Vector3,
	LastVelocity: Vector3,
	LastTimestamp: number,
}

export type ScriptConnection = {
	Connected: boolean,
	Disconnect: (self: ScriptConnection) -> (),
}

export type ScriptSignal<Parameters...> = {
	Connect: (self: ScriptSignal<Parameters...>, (Parameters...) -> ()) -> ScriptConnection,
	Fire: (self: ScriptSignal<Parameters...>, ...any) -> (),
}

local RunService = game:GetService("RunService")

local IS_SERVER = RunService:IsServer()

local CONFIG = {
	FolderParent       = script,
	NameDictionary     = {
		Folder           = "NetworkInstances",
		Request          = "____Request",        -- RemoteFunction (handshake)
		UnreliableEvent  = "____Unreliable",     -- UnreliableRemoteEvent (fast channel)
		Reliable         = "____Event",          -- RemoteEvent (reliable channel)
		Ack              = "____Ack",            -- RemoteEvent (acknowledgment channel)
	},

	-- FIX: defaults to false — should not be true in shipped code
	VerboseDebug       = false,

	Timeout            = 10,    -- Seconds to wait before WaitForChild gives up
	NonceLength        = 6,     -- Character length of each generated nonce
	NonceExpiry        = 10,    -- Seconds before a seen nonce is cleared from memory
	StreamWindow       = 64,    -- Reject nodes this many positions behind or ahead of NextExpected
	RetransmitInterval = 0.2,   -- Seconds between retransmit attempts for buffered reliable nodes
	MaxRetries         = 8,     -- Drop a buffered node after this many failed retransmit attempts
	SessionExpiry      = 3600,  -- Seconds before a session token is considered stale
	SecretRotation     = 30,    -- Seconds between per-session secret rotations

	-- FIX: rate-limit the handshake RemoteFunction to prevent session-spam
	HandshakeCooldown  = 5,     -- Seconds a player must wait before a second handshake is accepted

	-- Rate limiting (token bucket)
	BucketCapacity     = 100,   -- Max burst tokens per player
	BucketRefillRate   = 20,    -- Tokens restored per second

	-- Per-stream token costs (default 1 if not listed)
	StreamCosts        = {} :: { [number]: number },

	-- Dead reckoning
	PositionThreshold  = 20,    -- Studs — flag if reported pos deviates more than this from prediction

	-- Bandwidth tracking
	BandwidthWindow       = 1,  -- Seconds per measurement window
	PacketsPerSecondLimit = 60, -- Packets/sec above which anomaly is flagged
	MaxViolations         = 5,  -- Violations before the player is kicked
}

-- Framework
local Framework do
	local options = {
		VerboseDebug = CONFIG.VerboseDebug,
	}

	local SignalClass = {}
	SignalClass.__index = SignalClass

	type SignalInternal = {
		_nextId: number,
		_conns: { [number]: ScriptConnection },
		_count: number,
	}

	function SignalClass:Connect(callback): ScriptConnection
		assert(type(callback) == "function", "Signal:Connect expects a function");
		(self :: SignalInternal)._nextId += 1
		local id   = (self :: SignalInternal)._nextId
		local conn = {
			Connected  = true,
			Disconnect = function(s)
				if not s.Connected then return end
				s.Connected                             = false
				(self :: SignalInternal)._conns[id]     = nil
				(self :: SignalInternal)._count         = math.max(0, (self :: SignalInternal)._count - 1)
			end,
			_callback  = callback,
		}
		(self :: SignalInternal)._conns[id] = conn;
		(self :: SignalInternal)._count    += 1
		return conn :: ScriptConnection
	end

	function SignalClass:Fire(...)
		if self._count == 0 then return end
		local args     = table.pack(...)
		local snapshot = {}
		for _, c in pairs(self._conns) do
			snapshot[#snapshot + 1] = c
		end
		for _, c in ipairs(snapshot) do
			if c and (c :: ScriptConnection).Connected and type((c :: any)._callback) == "function" then
				task.spawn(function()
					local ok, err = pcall((c :: any)._callback, table.unpack(args, 1, args.n))
					if not ok then
						Framework.Utils.Log("Signal callback error: %s", tostring(err))
					end
				end)
			end
		end
	end

	Framework = {
		Utils = {},
		CreateSignal = function()
			return setmetatable({
				_conns  = {},
				_count  = 0,
				_nextId = 0,
			}, SignalClass) :: any
		end,
	}

	function Framework.Utils.Log(message: string, ...)
		if options.VerboseDebug then
			print(string.format("[NET] " .. (message :: any), ...))
		end
	end

	function Framework.Utils.MakeDictionaryFromTuple(...)
		local t = {}
		for i, inst in pairs(table.pack(...)) do
			if (i :: string | number) == "n" then continue end
			t[inst.Name] = inst
		end
		return t
	end

	function Framework.Utils.Sign(a: string, b: string): string
		if #a == 0 or #b == 0 then return "00000000" end
		local result = 0
		local bLen   = #b
		for i = 1, #a do
			local byte       = string.byte(a, i)
			local secretByte = string.byte(b, ((i - 1) % bLen) + 1)
			result = bit32.bxor(result, bit32.bxor(byte, secretByte))
			result = bit32.band(bit32.lrotate(result, 5), 0xFFFFFFFF)
		end
		return string.format("%08X", result)
	end

	function Framework.Utils.Nonce(): string
		local chars   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		local result  = {}
		local entropy = bit32.band(math.floor(tick() * 1e6), 0xFFFF)
		for i = 1, CONFIG.NonceLength do
			local randomIndex = bit32.band(bit32.bxor(math.random(1, #chars), entropy + i), 0x3F) % #chars + 1
			result[i] = string.sub(chars, randomIndex, randomIndex)
		end
		return table.concat(result)
	end

	function Framework.Utils.Encode(t: { [any]: any }): string
		local parts = {}
		local keys  = {}
		for k in pairs(t) do
			keys[#keys + 1] = tostring(k)
		end
		table.sort(keys)
		for _, k in ipairs(keys) do
			local v = t[k]
			if type(v) == "table" then
				parts[#parts + 1] = k .. "={" .. Framework.Utils.Encode(v) .. "}"
			else
				parts[#parts + 1] = k .. "=" .. tostring(v)
			end
		end
		return table.concat(parts, "|")
	end

	function Framework.Utils.GenerateSecret(): string
		local a = math.random(0x1000, 0xFFFF)
		local b = math.random(0x1000, 0xFFFF)
		local c = math.floor(tick() * 1000) % 0xFFFF
		return string.format("%04X%04X%04X", a, c, b)
	end
end

-- Creates the NET folder on the server, or waits for it on the client.
local function makeOrGetFolder(): Folder?
	if IS_SERVER then
		local existing = CONFIG.FolderParent:FindFirstChild(CONFIG.NameDictionary.Folder)
		if existing then return existing :: Folder end
		local folder  = Instance.new("Folder")
		folder.Name   = CONFIG.NameDictionary.Folder
		folder.Parent = CONFIG.FolderParent
		return folder
	else
		local folder = CONFIG.FolderParent:WaitForChild(CONFIG.NameDictionary.Folder, CONFIG.Timeout)
		if not folder then
			Framework.Utils.Log("Timed out waiting for Folder in CONFIG.FolderParent")
			return nil
		end
		return folder :: Folder
	end
end

local function getOrSetupRemotes(): { [string]: RemoteEvent | UnreliableRemoteEvent | RemoteFunction }
	local folder = makeOrGetFolder()
	if not folder then return (nil :: any) end

	if IS_SERVER then
		local function createOrGet(name: string, className: string)
			local existing = folder:FindFirstChild(name)
			if existing then return existing end
			local r   = Instance.new(className) :: any
			r.Name    = name
			r.Parent  = folder
			return r
		end
		return Framework.Utils.MakeDictionaryFromTuple(
			createOrGet(CONFIG.NameDictionary.Request,         "RemoteFunction"),
			createOrGet(CONFIG.NameDictionary.UnreliableEvent, "UnreliableRemoteEvent"),
			createOrGet(CONFIG.NameDictionary.Reliable,        "RemoteEvent"),
			createOrGet(CONFIG.NameDictionary.Ack,             "RemoteEvent")
		)
	else
		local function get(name: string)
			return folder:WaitForChild(name, CONFIG.Timeout)
		end
		local request    = get(CONFIG.NameDictionary.Request)         :: RemoteFunction
		local unreliable = get(CONFIG.NameDictionary.UnreliableEvent) :: UnreliableRemoteEvent
		local reliable   = get(CONFIG.NameDictionary.Reliable)        :: RemoteEvent
		local ack        = get(CONFIG.NameDictionary.Ack)             :: RemoteEvent
		if not request or not unreliable or not reliable or not ack then
			Framework.Utils.Log("Timed out waiting for one or more remotes")
			return (nil :: any)
		end
		return Framework.Utils.MakeDictionaryFromTuple(request, unreliable, reliable, ack)
	end
end

local Remotes          = getOrSetupRemotes()
local ReliableRemote   = Remotes and Remotes[CONFIG.NameDictionary.Reliable]        :: RemoteEvent
local UnreliableRemote = Remotes and Remotes[CONFIG.NameDictionary.UnreliableEvent] :: UnreliableRemoteEvent
local AckRemote        = Remotes and Remotes[CONFIG.NameDictionary.Ack]             :: RemoteEvent
local HandshakeRemote  = Remotes and Remotes[CONFIG.NameDictionary.Request]         :: RemoteFunction

-- Internal state
local NET = {
	Streams           = {} :: { [number]: Stream },
	ReceiveSignals    = {} :: { [number]: ScriptSignal<Player?, any> },
	SeenNonces        = {} :: { [string]: number },
	Sessions          = {} :: { [Player]: Session },
	TokenBuckets      = {} :: { [Player]: TokenBucket },
	AnomalyStats      = {} :: { [Player]: { count: number, window: number, violations: number } },
	Bandwidth         = {} :: { [Player]: BandwidthSample },
	DeadReckon        = {} :: { [Player]: DeadReckonSample },
	OutgoingQueue     = {} :: { [Player]: { [string]: { Node } } },
	PingTimestamps    = {} :: { [Player]: number },
	RTT               = {} :: { [Player]: number },
	ReadyPlayers      = {} :: { [Player]: boolean },
	PendingReceive    = {} :: { [number]: { { callback: (...any) -> () } } },

	-- FIX: per-player send buffers — [player][streamId][seq] = BufferedNode
	-- Keeping buffers per-player means the retransmit loop always has a FireClient target.
	SendBuffers       = {} :: { [Player]: { [number]: { [number]: BufferedNode } } },

	-- FIX: tracks when each player last completed a handshake for rate-limiting
	HandshakeLastSeen = {} :: { [Player]: number },

	ClientSecret      = nil :: string?,
	ClientToken       = nil :: string?,

	-- FIX: client-side upload bandwidth sample (mirrors server Bandwidth but for the client)
	ClientBandwidth   = nil :: BandwidthSample?,
}

-- Public API
local NETPublic = {
	OnStateCleanup            = Framework.CreateSignal() :: ScriptSignal<Player>,
	OnAnomalyDetected         = Framework.CreateSignal() :: ScriptSignal<Player, string>,
	OnCriticalAnomalyDetected = Framework.CreateSignal() :: ScriptSignal<Player, string>,
	OnInvalidSequence         = Framework.CreateSignal() :: ScriptSignal<Stream, number>,
	-- FIX: correctly typed as single-arg — was being fired as (player, node) before
	OnRateLimit               = Framework.CreateSignal() :: ScriptSignal<Player>,
	OnUnacknowledgedNode      = Framework.CreateSignal() :: ScriptSignal<number, number, BufferedNode>,
	-- FIX: these three were fired in receiveFromClient but never declared
	OnInvalidNodeFromClient   = Framework.CreateSignal() :: ScriptSignal<Player, Node>,
	OnInvalidSession          = Framework.CreateSignal() :: ScriptSignal<Player, string>,
	OnInvalidSignature        = Framework.CreateSignal() :: ScriptSignal<Player, Node>,
	OnNodeProcessed           = Framework.CreateSignal() :: ScriptSignal<Node, Player?>,
}
NETPublic.__index = NETPublic

-- Internal Helpers

local function getOrCreateBucket(player: Player): TokenBucket
	if not NET.TokenBuckets[player] then
		NET.TokenBuckets[player] = { Tokens = CONFIG.BucketCapacity, LastRefill = tick() }
	end
	return NET.TokenBuckets[player]
end

local function consumeToken(player: Player, cost: number?): boolean
	local c       = cost or 1
	local bucket  = getOrCreateBucket(player)
	local now     = tick()
	local elapsed = now - bucket.LastRefill
	bucket.Tokens     = math.min(CONFIG.BucketCapacity, bucket.Tokens + elapsed * CONFIG.BucketRefillRate)
	bucket.LastRefill = now
	if bucket.Tokens >= c then
		bucket.Tokens -= c
		return true
	end
	return false
end

local function trackAnomaly(player: Player)
	local stats = NET.AnomalyStats[player]
	if not stats then
		NET.AnomalyStats[player] = { count = 0, window = tick(), violations = 0 }
		stats = NET.AnomalyStats[player]
	end
	stats.count += 1
	if tick() - stats.window >= 1 then
		if stats.count > CONFIG.PacketsPerSecondLimit then
			stats.violations += 1
			local message = string.format(
				"Anomaly detected for %s — pps: %d (violation %d/%d)",
				player.Name, stats.count, stats.violations, CONFIG.MaxViolations
			)
			Framework.Utils.Log(message)
			NETPublic.OnAnomalyDetected:Fire(player, message)
			if stats.violations >= CONFIG.MaxViolations then
				Framework.Utils.Log("Critical anomaly detected for %s", player.Name)
				NETPublic.OnCriticalAnomalyDetected:Fire(player, string.format("Critical anomaly detected for %s", player.Name))
			end
		end
		stats.count  = 0
		stats.window = tick()
	end
end

local function trackBandwidth(player: Player, bytes: number)
	local sample = NET.Bandwidth[player]
	if not sample then
		NET.Bandwidth[player] = { BytesThisWindow = 0, WindowStart = tick(), EstimatedBps = 0 }
		sample = NET.Bandwidth[player]
	end
	sample.BytesThisWindow += bytes
	if tick() - sample.WindowStart >= CONFIG.BandwidthWindow then
		sample.EstimatedBps    = sample.BytesThisWindow
		sample.BytesThisWindow = 0
		sample.WindowStart     = tick()
	end
end

-- FIX: client-side upload bandwidth tracking — no Player key needed
local function trackClientBandwidth(bytes: number)
	if not NET.ClientBandwidth then
		NET.ClientBandwidth = { BytesThisWindow = 0, WindowStart = tick(), EstimatedBps = 0 }
	end
	local sample = NET.ClientBandwidth :: BandwidthSample
	sample.BytesThisWindow += bytes
	if tick() - sample.WindowStart >= CONFIG.BandwidthWindow then
		sample.EstimatedBps    = sample.BytesThisWindow
		sample.BytesThisWindow = 0
		sample.WindowStart     = tick()
	end
end

local function isValidSequence(stream: Stream, incomingSeq: number): boolean
	local expected = stream.NextExpected
	if incomingSeq <= expected - CONFIG.StreamWindow then NETPublic.OnInvalidSequence:Fire(stream, incomingSeq) return false end
	if incomingSeq >  expected + CONFIG.StreamWindow then NETPublic.OnInvalidSequence:Fire(stream, incomingSeq) return false end
	return true
end

local function isReplay(nonce: string, timestamp: number): boolean
	if NET.SeenNonces[nonce] then return true end
	if math.abs(tick() - timestamp) > CONFIG.NonceExpiry then return true end
	NET.SeenNonces[nonce] = tick()
	return false
end

local function isValidSession(player: Player, token: string): boolean
	local session = NET.Sessions[player]
	if not session then return false end
	if session.Token ~= token then return false end
	if tick() - session.CreatedAt > CONFIG.SessionExpiry then return false end
	session.LastSeen = tick()
	return true
end

local function isValidSignature(player: Player, node: Node): boolean
	local session = NET.Sessions[player]
	if not session then return false end
	local sig      = node.Signature
	node.Signature = ""
	local expected = Framework.Utils.Sign(Framework.Utils.Encode(node :: any), session.Secret)
	node.Signature = sig
	return sig == expected
end

local function isSuspiciousPosition(player: Player, position: Vector3, velocity: Vector3): boolean
	local sample = NET.DeadReckon[player]
	if not sample then
		NET.DeadReckon[player] = { LastPosition = position, LastVelocity = velocity, LastTimestamp = tick() }
		return false
	end
	local dt        = tick() - sample.LastTimestamp
	local predicted = sample.LastPosition + sample.LastVelocity * dt
	local deviation = (predicted - position).Magnitude
	sample.LastPosition  = position
	sample.LastVelocity  = velocity
	sample.LastTimestamp = tick()
	return deviation > CONFIG.PositionThreshold
end

local function encodeNode(node: Node): string
	local copy     = table.clone(node :: any)
	copy.Signature = nil
	return Framework.Utils.Encode(copy)
end

local function signNode(node: Node, secret: string): string
	return Framework.Utils.Sign(encodeNode(node), secret)
end

local function createStream(id: number, reliable: boolean): Stream
	return {
		Id            = id,
		Reliable      = reliable,
		NextExpected  = 0,
		SendSequence  = 0,
		SendBuffer    = {},
		ReceiveBuffer = {},
	}
end

local function registerStreamLocal(identifier: number, reliable: boolean)
	if NET.Streams[identifier] then return end
	NET.Streams[identifier]        = createStream(identifier, reliable)
	NET.ReceiveSignals[identifier] = Framework.CreateSignal() :: ScriptSignal<any>
	Framework.Utils.Log("Registered stream %d (reliable=%s)", identifier, tostring(reliable))
end

local function processNode(player: Player?, node: Node)
	local stream = NET.Streams[node.StreamId]
	if not stream then return end

	local function fireSignal(signal: ScriptSignal<any>, payload: any)
		if not signal then return end
		if player then
			signal:Fire(player, payload)
		else
			signal:Fire(payload)
		end
	end

	if stream.Reliable then
		if node.Position == stream.NextExpected + 1 then
			stream.NextExpected += 1
			local signal = NET.ReceiveSignals[node.StreamId]
			fireSignal(signal, node.Payload)
			while stream.ReceiveBuffer[stream.NextExpected + 1] do
				stream.NextExpected += 1
				local buffered = stream.ReceiveBuffer[stream.NextExpected]
				stream.ReceiveBuffer[stream.NextExpected] = nil
				fireSignal(signal, buffered.Payload)
			end
		elseif node.Position > stream.NextExpected + 1 then
			stream.ReceiveBuffer[node.Position] = node
		end
	else
		local signal = NET.ReceiveSignals[node.StreamId]
		fireSignal(signal, node.Payload)
	end

	NETPublic.OnNodeProcessed:Fire(node, player)
end

local function receiveFromClient(player: Player, node: Node)
	if not isValidSession(player, node.Token) then
		Framework.Utils.Log("Invalid session token from %s on stream %d", player.Name, node.StreamId)
		NETPublic.OnInvalidSession:Fire(player, node.Token)
		return
	end

	if isReplay(node.Nonce, node.Timestamp) then
		Framework.Utils.Log("Replay or stale node from %s on stream %d", player.Name, node.StreamId)
		NETPublic.OnInvalidNodeFromClient:Fire(player, node)
		return
	end

	local stream = NET.Streams[node.StreamId]
	if not stream then
		Framework.Utils.Log("Unknown stream %d from %s", node.StreamId, player.Name)
		return
	end

	if not isValidSequence(stream, node.Position) then
		Framework.Utils.Log("Out-of-window sequence from %s on stream %d", player.Name, node.StreamId)
		return
	end

	if not isValidSignature(player, node) then
		Framework.Utils.Log("Invalid signature from %s on stream %d", player.Name, node.StreamId)
		NETPublic.OnInvalidSignature:Fire(player, node)
		return
	end

	local cost = CONFIG.StreamCosts[node.StreamId] or 1
	if not consumeToken(player, cost) then
		Framework.Utils.Log("Rate limit exceeded for %s on stream %d", player.Name, node.StreamId)
		-- FIX: fire with only player — matches ScriptSignal<Player>
		NETPublic.OnRateLimit:Fire(player)
		return
	end

	trackAnomaly(player)

	if node.Reliable then
		AckRemote:FireClient(player, { StreamId = node.StreamId, AckPosition = node.Position })
	end

	processNode(player, node)
end

-- FIX: now clears from NET.SendBuffers[player][streamId] instead of the defunct stream.SendBuffer
local function receiveAckFromClient(player: Player, ack: { StreamId: number, AckPosition: number })
	local playerBuffers = NET.SendBuffers[player]
	if not playerBuffers then return end
	local streamBuffer = playerBuffers[ack.StreamId]
	if not streamBuffer then return end
	streamBuffer[ack.AckPosition] = nil
end

local function receiveFromServer(node: Node)
	local stream = NET.Streams[node.StreamId]
	if not stream then return end
	if node.Reliable then
		AckRemote:FireServer({ StreamId = node.StreamId, AckPosition = node.Position })
	end
	processNode(nil, node)
end

local function receiveAckFromServer(ack: { StreamId: number, AckPosition: number })
	local stream = NET.Streams[ack.StreamId]
	if not stream then return end
	stream.SendBuffer[ack.AckPosition] = nil
end

local function buildAndQueue(streamId: number, payload: any, player: Player?)
	local stream = NET.Streams[streamId]
	if not stream then
		Framework.Utils.Log("Attempted to send on unregistered stream %d", streamId)
		return
	end

	stream.SendSequence += 1

	local node: Node = {
		StreamId  = streamId,
		Position  = stream.SendSequence,
		AckNumber = stream.NextExpected,
		Reliable  = stream.Reliable,
		Nonce     = Framework.Utils.Nonce(),
		Timestamp = tick(),
		Token     = (IS_SERVER and "") or (NET.ClientToken or ""),
		Signature = "",
		Payload   = payload,
	}

	local secret = ""
	if IS_SERVER and player then
		local session = NET.Sessions[player]
		if session then secret = session.Secret end
	elseif not IS_SERVER then
		secret = NET.ClientSecret or ""
	end
	node.Signature = signNode(node, secret)

	if IS_SERVER then
		if not player then return end
		if not NET.OutgoingQueue[player] then
			NET.OutgoingQueue[player] = { reliable = {}, unreliable = {} }
		end
		local channel = stream.Reliable and "reliable" or "unreliable"
		table.insert(NET.OutgoingQueue[player][channel], node)

		-- FIX: buffer into per-player table so the retransmit loop has a FireClient target
		if stream.Reliable then
			if not NET.SendBuffers[player] then
				NET.SendBuffers[player] = {}
			end
			if not NET.SendBuffers[player][streamId] then
				NET.SendBuffers[player][streamId] = {}
			end
			NET.SendBuffers[player][streamId][stream.SendSequence] = {
				Node    = node,
				SentAt  = tick(),
				Retries = 0,
			}
		end

		trackBandwidth(player, #Framework.Utils.Encode(node :: any))
	else
		-- FIX: track client upload bandwidth
		trackClientBandwidth(#Framework.Utils.Encode(node :: any))

		if stream.Reliable then
			ReliableRemote:FireServer(node)
			stream.SendBuffer[stream.SendSequence] = {
				Node    = node,
				SentAt  = tick(),
				Retries = 0,
			}
		else
			UnreliableRemote:FireServer(node)
		end
	end
end

-- Flush outgoing batch queue every Heartbeat (server)
if IS_SERVER then
	RunService.Heartbeat:Connect(function()
		for player, queues in pairs(NET.OutgoingQueue) do
			if not NET.ReadyPlayers[player] then continue end
			if #queues.reliable > 0 then
				ReliableRemote:FireClient(player, queues.reliable)
				NET.OutgoingQueue[player].reliable = {}
			end
			if #queues.unreliable > 0 then
				UnreliableRemote:FireClient(player, queues.unreliable)
				NET.OutgoingQueue[player].unreliable = {}
			end
		end
	end)
end

-- FIX: Retransmit loop is now correctly split by side.
-- Server iterates NET.SendBuffers[player][streamId][seq] so it always has a player for FireClient.
-- Client iterates stream.SendBuffer as before — it only ever sends to the server.
RunService.Heartbeat:Connect(function()
	if IS_SERVER then
		for player, streamBuffers in pairs(NET.SendBuffers) do
			for streamId, buffer in pairs(streamBuffers) do
				for seq, buffered in pairs(buffer) do
					if tick() - buffered.SentAt >= CONFIG.RetransmitInterval then
						buffered.Retries += 1
						if buffered.Retries > CONFIG.MaxRetries then
							Framework.Utils.Log(
								"Dropping unacknowledged node for %s on stream %d seq %d after %d retries",
								player.Name, streamId, seq, buffered.Retries
							)
							buffer[seq] = nil
							NETPublic.OnUnacknowledgedNode:Fire(streamId, seq, buffered)
							continue
						end
						buffered.SentAt = tick()
						ReliableRemote:FireClient(player, { buffered.Node })
					end
				end
			end
		end
	else
		for _, stream in pairs(NET.Streams) do
			if not stream.Reliable then continue end
			for seq, buffered in pairs(stream.SendBuffer) do
				if tick() - buffered.SentAt >= CONFIG.RetransmitInterval then
					buffered.Retries += 1
					if buffered.Retries > CONFIG.MaxRetries then
						Framework.Utils.Log(
							"Dropping unacknowledged node on stream %d seq %d after %d retries",
							stream.Id, seq, buffered.Retries
						)
						stream.SendBuffer[seq] = nil
						NETPublic.OnUnacknowledgedNode:Fire(stream.Id, seq, buffered)
						continue
					end
					buffered.SentAt = tick()
					ReliableRemote:FireServer(buffered.Node)
				end
			end
		end
	end
end)

-- Purge expired nonces (server)
if IS_SERVER then
	task.spawn(function()
		while true do
			task.wait(CONFIG.NonceExpiry)
			local now = tick()
			for nonce, t in pairs(NET.SeenNonces) do
				if (now - t) > CONFIG.NonceExpiry then
					NET.SeenNonces[nonce] = nil
				end
			end
		end
	end)
end

-- FIX: Secret rotation messages are now signed with the CURRENT (old) secret before it is
-- replaced, so the client can verify authenticity. A client that receives a spoofed rotation
-- with an unknown signature will reject it and keep its current secret.
if IS_SERVER then
	task.spawn(function()
		while true do
			task.wait(CONFIG.SecretRotation)
			for player, session in pairs(NET.Sessions) do
				local newSecret = Framework.Utils.GenerateSecret()

				local rotationNode = {
					StreamId  = -1,
					Position  = -1,
					AckNumber = -1,
					Reliable  = true,
					Nonce     = Framework.Utils.Nonce(),
					Timestamp = tick(),
					Token     = session.Token,
					Signature = "",
					Payload   = { __type = "SECRET_ROTATION", secret = newSecret },
				}
				-- Sign with the OLD secret so the client can verify before accepting
				rotationNode.Signature = Framework.Utils.Sign(
					Framework.Utils.Encode(rotationNode :: any),
					session.Secret
				)

				-- Update AFTER signing so the signature is still valid against the old secret
				session.Secret = newSecret

				ReliableRemote:FireClient(player, { rotationNode })
				Framework.Utils.Log("Rotated secret for %s", player.Name)
			end
		end
	end)
end

-- RTT ping loop (server → clients, every 5 seconds)
if IS_SERVER then
	task.spawn(function()
		while true do
			task.wait(5)
			for player, session in pairs(NET.Sessions) do
				NET.PingTimestamps[player] = tick()
				ReliableRemote:FireClient(player, { {
					StreamId  = -1,
					Position  = -1,
					AckNumber = -1,
					Reliable  = false,
					Nonce     = Framework.Utils.Nonce(),
					Timestamp = tick(),
					Token     = session.Token,
					Signature = "",
					Payload   = { __type = "PING" },
				} })
			end
		end
	end)
end

-- Runtime wiring
if IS_SERVER then
	if HandshakeRemote then
		-- FIX: rate-limited handshake — rejects repeated invocations within HandshakeCooldown seconds
		HandshakeRemote.OnServerInvoke = function(player: Player)
			local now      = tick()
			local lastSeen = NET.HandshakeLastSeen[player]
			if lastSeen and (now - lastSeen) < CONFIG.HandshakeCooldown then
				Framework.Utils.Log("Handshake rate-limited for %s (%.1fs remaining)",
					player.Name, CONFIG.HandshakeCooldown - (now - lastSeen))
				return nil
			end
			NET.HandshakeLastSeen[player] = now

			local token  = Framework.Utils.Nonce() .. Framework.Utils.Nonce()
			local secret = Framework.Utils.GenerateSecret()

			NET.Sessions[player] = {
				Player    = player,
				Token     = token,
				Secret    = secret,
				CreatedAt = now,
				LastSeen  = now,
			}
			NET.OutgoingQueue[player] = { reliable = {}, unreliable = {} }
			NET.SendBuffers[player]   = {}
			Framework.Utils.Log("Session created for %s — token: %s", player.Name, token)

			local streamList = {}
			for id, stream in pairs(NET.Streams) do
				streamList[#streamList + 1] = { id = id, reliable = stream.Reliable }
			end

			return { token = token, secret = secret, streams = streamList }
		end
	end

	if ReliableRemote then
		ReliableRemote.OnServerEvent:Connect(function(player: Player, node: Node)
			if not node then return end
			if node.Payload and node.Payload.__type == "READY" then
				NET.ReadyPlayers[player] = true
				Framework.Utils.Log("%s is ready to receive.", player.Name)
				return
			end
			if node.Payload and node.Payload.__type == "PONG" then
				local sentAt = NET.PingTimestamps[player]
				if sentAt then
					NET.RTT[player]            = tick() - sentAt
					NET.PingTimestamps[player] = nil
					Framework.Utils.Log("RTT for %s: %dms", player.Name, math.floor(NET.RTT[player] * 1000))
				end
				return
			end
			receiveFromClient(player, node)
		end)
	end

	if UnreliableRemote then
		UnreliableRemote.OnServerEvent:Connect(function(player: Player, node: Node)
			if not node then return end
			receiveFromClient(player, node)
		end)
	end

	if AckRemote then
		AckRemote.OnServerEvent:Connect(function(player: Player, ack)
			if not ack then return end
			receiveAckFromClient(player, ack)
		end)
	end

	game:GetService("Players").PlayerRemoving:Connect(function(player: Player)
		NET.Sessions[player]          = nil
		NET.TokenBuckets[player]      = nil
		NET.AnomalyStats[player]      = nil
		NET.Bandwidth[player]         = nil
		NET.DeadReckon[player]        = nil  -- FIX: explicitly cleared so reconnecting players start fresh
		NET.OutgoingQueue[player]     = nil
		NET.PingTimestamps[player]    = nil
		NET.RTT[player]               = nil
		NET.ReadyPlayers[player]      = nil
		NET.SendBuffers[player]       = nil  -- FIX: clean up per-player retransmit buffers
		NET.HandshakeLastSeen[player] = nil  -- FIX: clean up handshake cooldown tracker
		NETPublic.OnStateCleanup:Fire(player)
		Framework.Utils.Log("Cleaned up state for %s", player.Name)
	end)

else
	if HandshakeRemote then
		task.spawn(function()
			local result = HandshakeRemote:InvokeServer()
			-- FIX: guard against nil result from a rate-limited handshake response
			if not result then
				Framework.Utils.Log("Handshake returned nil — server may have rate-limited this client.")
				return
			end

			NET.ClientToken  = result.token
			NET.ClientSecret = result.secret
			Framework.Utils.Log("Handshake complete — token: %s", result.token)

			if result.streams then
				for _, entry in ipairs(result.streams) do
					registerStreamLocal((entry :: any).id, (entry :: any).reliable)
				end
			end

			ReliableRemote:FireServer({
				StreamId  = -1,
				Position  = -1,
				AckNumber = -1,
				Reliable  = false,
				Nonce     = Framework.Utils.Nonce(),
				Timestamp = tick(),
				Token     = NET.ClientToken or "",
				Signature = "",
				Payload   = { __type = "READY" },
			})
		end)
	end

	if ReliableRemote then
		ReliableRemote.OnClientEvent:Connect(function(nodes: { Node })
			if type(nodes) ~= "table" then return end
			for _, node in ipairs(nodes) do
				if node.Payload and node.Payload.__type == "SECRET_ROTATION" then
					-- FIX: verify the rotation was signed by the server using the OLD (current) secret.
					-- Without this check a malicious client on another machine, or a man-in-the-middle,
					-- could spoof this message and force the client to adopt a known-secret.
					local receivedSig  = node.Signature
					local nodeCopy     = table.clone(node :: any)
					nodeCopy.Signature = ""
					local expectedSig  = Framework.Utils.Sign(
						Framework.Utils.Encode(nodeCopy),
						NET.ClientSecret or ""
					)
					if receivedSig ~= expectedSig then
						Framework.Utils.Log("SECRET_ROTATION rejected — invalid signature. Possible spoof attempt.")
					else
						NET.ClientSecret = node.Payload.secret
						Framework.Utils.Log("Secret rotated by server (signature verified).")
					end

				elseif node.Payload and node.Payload.__type == "PING" then
					ReliableRemote:FireServer({
						StreamId  = -1,
						Position  = -1,
						AckNumber = -1,
						Reliable  = false,
						Nonce     = Framework.Utils.Nonce(),
						Timestamp = tick(),
						Token     = NET.ClientToken or "",
						Signature = "",
						Payload   = { __type = "PONG" },
					})

				elseif node.Payload and node.Payload.__type == "STREAM_REGISTER" then
					registerStreamLocal(node.Payload.id, node.Payload.reliable)

				elseif node.Payload and node.Payload.__type == "STREAM_UNREGISTER" then
					-- FIX: handle server-initiated stream removal
					local id = node.Payload.id
					if NET.Streams[id] then
						NET.Streams[id]        = nil
						NET.ReceiveSignals[id] = nil
						Framework.Utils.Log("Stream %d unregistered by server.", id)
					end

				else
					receiveFromServer(node :: Node)
				end
			end
		end)
	end

	if UnreliableRemote then
		UnreliableRemote.OnClientEvent:Connect(function(nodes: { Node })
			if type(nodes) ~= "table" then return end
			for _, node in ipairs(nodes) do
				receiveFromServer(node)
			end
		end)
	end

	if AckRemote then
		AckRemote.OnClientEvent:Connect(function(ack)
			if not ack then return end
			receiveAckFromServer(ack)
		end)
	end
end

--[[
Registers a new stream on this peer.
Must be called on both server and client with matching arguments before
any nodes are sent or received on that stream.

@param identifier: number   - Unique stream ID (e.g. 1, 2, 3)
@param reliable:   boolean  - true = TCP; false = UDP
]]
function NETPublic:RegisterStream(identifier: number, reliable: boolean)
	assert(type(identifier) == "number",  "RegisterStream: identifier must be a number")
	assert(type(reliable)   == "boolean", "RegisterStream: reliable must be a boolean")

	if NET.Streams[identifier] then
		Framework.Utils.Log("Stream %d is already registered, skipping.", identifier)
		return
	end

	registerStreamLocal(identifier, reliable)

	if IS_SERVER then
		for player, session in pairs(NET.Sessions) do
			ReliableRemote:FireClient(player, { {
				StreamId  = -1,
				Position  = -1,
				AckNumber = -1,
				Reliable  = true,
				Nonce     = Framework.Utils.Nonce(),
				Timestamp = tick(),
				Token     = session.Token,
				Signature = "",
				Payload   = { __type = "STREAM_REGISTER", id = identifier, reliable = reliable },
			} })
		end
	end
end

--[[
Unregisters a stream, removing it from both the stream table and the receive-signal table.
Any buffered nodes for this stream are discarded. On the server, all connected clients are
notified so they unregister their local copy too.

@param identifier: number  - The stream ID to remove
]]
function NETPublic:UnregisterStream(identifier: number)
	assert(type(identifier) == "number", "UnregisterStream: identifier must be a number")

	if not NET.Streams[identifier] then
		Framework.Utils.Log("UnregisterStream: stream %d is not registered, skipping.", identifier)
		return
	end

	NET.Streams[identifier]        = nil
	NET.ReceiveSignals[identifier] = nil

	if IS_SERVER then
		-- Drop all buffered nodes for this stream across every player
		for _, streamBuffers in pairs(NET.SendBuffers) do
			streamBuffers[identifier] = nil
		end

		-- Notify connected clients to drop their local registration
		for player, session in pairs(NET.Sessions) do
			ReliableRemote:FireClient(player, { {
				StreamId  = -1,
				Position  = -1,
				AckNumber = -1,
				Reliable  = true,
				Nonce     = Framework.Utils.Nonce(),
				Timestamp = tick(),
				Token     = session.Token,
				Signature = "",
				Payload   = { __type = "STREAM_UNREGISTER", id = identifier },
			} })
		end
	end

	Framework.Utils.Log("Unregistered stream %d", identifier)
end

--[[
Sends a payload on the given stream.

Server usage: NET:Send(player, streamId, payload)
Client usage: NET:Send(streamId, payload)
]]
function NETPublic:Send(...): ()
	local args = { ... }
	if IS_SERVER then
		local player:   Player         = args[1]
		local streamId: number         = args[2]
		local payload:  { [any]: any } = args[3]
		assert(typeof(player)   == "Instance", "Send (server): first argument must be a Player")
		assert(type(streamId)   == "number",   "Send (server): second argument must be a stream ID")
		assert(type(payload)    == "table",    "Send (server): third argument must be a table")
		buildAndQueue(streamId, payload, player)
	else
		local streamId: number         = args[1]
		local payload:  { [any]: any } = args[2]
		assert(type(streamId) == "number", "Send (client): first argument must be a stream ID")
		assert(type(payload)  == "table",  "Send (client): second argument must be a table")
		buildAndQueue(streamId, payload, nil)
	end
end

--[[
Registers a callback to fire when a node is received on the given stream.

Server callback: function(player: Player, data: {[any]: any})
Client callback: function(data: {[any]: any})

@param streamId: number
@param callback: (...any) -> ()
@returns ScriptConnection
]]
function NETPublic.OnReceive(streamId: number, callback: (...any) -> ()): ScriptConnection
	assert(NET.ReceiveSignals[streamId], "OnReceive: stream " .. tostring(streamId) .. " is not registered")
	return NET.ReceiveSignals[streamId]:Connect(callback)
end

--[[
Returns the most recently measured RTT for a player in seconds.
SERVER ONLY.

@param player: Player
@returns number?  - RTT in seconds, or nil if not yet measured
]]
function NETPublic:GetRTT(player: Player): number?
	assert(IS_SERVER, "GetRTT is only available on the server")
	return NET.RTT[player]
end

--[[
Returns the estimated outgoing bandwidth to a player in bytes per second.
SERVER ONLY.

@param player: Player
@returns number
]]
function NETPublic:GetBandwidth(player: Player): number
	assert(IS_SERVER, "GetBandwidth is only available on the server")
	local sample = NET.Bandwidth[player]
	return sample and sample.EstimatedBps or 0
end

--[[
Returns the estimated upload bandwidth from this client to the server in bytes per second.
CLIENT ONLY.

@returns number
]]
function NETPublic:GetClientBandwidth(): number
	assert(not IS_SERVER, "GetClientBandwidth is only available on the client")
	local sample = NET.ClientBandwidth
	return sample and sample.EstimatedBps or 0
end

--[[
Validates a reported movement position using dead reckoning.
Returns true if the position appears suspicious (too far from predicted location).
SERVER ONLY.

@param player:   Player
@param position: Vector3
@param velocity: Vector3
@returns boolean
]]
function NETPublic:IsSuspiciousPosition(player: Player, position: Vector3, velocity: Vector3): boolean
	assert(IS_SERVER, "IsSuspiciousPosition is only available on the server")
	return isSuspiciousPosition(player, position, velocity)
end

--[[
Clears the dead-reckoning sample for a player so that the next reported position
is treated as a new baseline rather than compared against stale prediction data.
Call this whenever a player teleports or respawns to avoid false positives.
SERVER ONLY.

@param player: Player
]]
function NETPublic:ResetDeadReckon(player: Player)
	assert(IS_SERVER, "ResetDeadReckon is only available on the server")
	NET.DeadReckon[player] = nil
	Framework.Utils.Log("Dead-reckoning sample reset for %s", player.Name)
end

--[[
Returns the current session for a player, or nil if none exists.
SERVER ONLY.

@param player: Player
@returns Session?
]]
function NETPublic:GetSession(player: Player): Session?
	assert(IS_SERVER, "GetSession is only available on the server")
	return NET.Sessions[player]
end

--[[
Returns the active stream table for a given stream ID, or nil.

@param streamId: number
@returns Stream?
]]
function NETPublic:GetStream(streamId: number): Stream?
	return NET.Streams[streamId]
end

setmetatable(NET, {
	__index = function(_, k)
		local method = NETPublic[k]
		if method then return method end
		if rawget(NET :: any, k) ~= nil then return rawget(NET :: any, k) :: any end
		error(("Attempt to index NET with unknown key '%s'"):format(tostring(k)), 2)
	end,
	__tostring = function()
		return "NET"
	end,
	__metatable = "LockedMeta",
})

return NET :: typeof(NETPublic)
