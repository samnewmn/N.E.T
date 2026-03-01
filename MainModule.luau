--[[
	NET - Node Exchange Transport
	
	A QUIC-inspired networking module built on top of Roblox's RemoteEvent primitives.
	Provides multiplexed streams, reliable delivery, authenticity checking, rate limiting,
	replay prevention, session management, dead reckoning, and bandwidth estimation.
	
	Architecture:
		Client                          Server
		  |                               |
		  |--- UnreliableRemote (node) -->|
		  |--- ReliableRemote  (node) --->|
		  |                               |-- StreamManager:Receive()
		  |                               |-- Pipeline: Validate → Auth → RateLimit → Process
		  |<-- AckRemote       (ack)  ----|
		  |<-- ReliableRemote  (node) ----|
	
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
	SendBuffer: { [number]: BufferedNode },   -- Unacknowledged reliable nodes
	ReceiveBuffer: { [number]: Node },         -- Out-of-order nodes awaiting gap fill
}

export type Node = {
	StreamId: number,     -- Stream this node belongs to
	Position: number,     -- Position of this node in the stream (sequence number)
	AckNumber: number,    -- Last position we have confirmed receiving from sender
	Reliable: boolean,    -- Whether this node expects acknowledgment
	Nonce: string,        -- Unique nonce for replay prevention
	Timestamp: number,    -- tick() at send time, used for expiry checks
	Token: string,        -- Session token for authenticity
	Signature: string,    -- HMAC-style signature of the serialised payload
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

export type ScriptSignal = {
	Connect: (self: ScriptSignal, (...any) -> ()) -> ScriptConnection,
	Fire: (self: ScriptSignal, ...any) -> (),
}

local RunService = game:GetService("RunService")

local IS_SERVER = RunService:IsServer()

local CONFIG = {
	FolderParent       = script,                -- Where the remote instances live
	NameDictionary     = {
		Folder           = "NetworkInstances",
		Request          = "____Request",        -- RemoteFunction (handshake)
		UnreliableEvent  = "____Unreliable",     -- UnreliableRemoteEvent (fast channel)
		Reliable         = "____Event",          -- RemoteEvent           (reliable channel)
		Ack              = "____Ack",            -- RemoteEvent           (acknowledgment channel)
	},
	VerboseDebug       = false,   -- Print logs and extra information
	Timeout            = 10,     -- Seconds to wait before WaitForChild gives up
	NonceLength        = 6,      -- Character length of each generated nonce
	NonceExpiry        = 10,     -- Seconds before a seen nonce is cleared from memory
	StreamWindow       = 64,     -- Reject nodes this many positions behind or ahead of NextExpected
	RetransmitInterval = 0.2,    -- Seconds between retransmit attempts for buffered reliable nodes
	MaxRetries         = 8,      -- Drop a buffered node after this many failed retransmit attempts
	SessionExpiry      = 3600,   -- Seconds before a session token is considered stale
	SecretRotation     = 30,     -- Seconds between per-session secret rotations
	-- Rate limiting (token bucket)
	BucketCapacity     = 100,    -- Max burst tokens per player
	BucketRefillRate   = 20,     -- Tokens restored per second
	-- Per-stream token costs (default 1 if not listed)
	StreamCosts        = {} :: { [number]: number },
	-- Dead reckoning
	PositionThreshold  = 20,     -- Studs — flag if reported pos deviates more than this from prediction
	-- Bandwidth tracking
	BandwidthWindow    = 1,      -- Seconds per measurement window
	-- Anomaly detection
	PacketsPerSecondLimit = 60,  -- Packets/sec above which anomaly is flagged
	MaxViolations         = 5,   -- Violations before the player is kicked
}

-- Framework
local Framework do
	local options = {
		VerboseDebug = CONFIG.VerboseDebug,
	}

	local Utils = {}
	Utils.__index = Utils

	function Utils.Log(message: string, ...)
		if options.VerboseDebug then
			print(string.format("[NET] " .. message, ...))
		end
	end

	function Utils.MakeDictionaryFromTuple(...)
		local t = {}
		for i, inst in pairs(table.pack(...)) do
			if i == "n" then continue end
			t[inst.Name] = inst
		end
		return t
	end

	function Utils.Sign(a: string, b: string): string
		if #a == 0 or #b == 0 then return "00000000" end
		local result = 0
		local bLen = #b
		for i = 1, #a do
			local byte       = string.byte(a, i)
			local secretByte = string.byte(b, ((i - 1) % bLen) + 1)  -- correct 1-based wrap
			result = bit32.bxor(result, bit32.bxor(byte, secretByte))
			result = bit32.band(bit32.lrotate(result, 5), 0xFFFFFFFF)
		end
		return string.format("%08X", result)
	end

	function Utils.Nonce(): string
		local chars  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		local result = {}
		-- Seed each character with tick-derived entropy XOR'd against a random index
		local entropy = bit32.band(math.floor(tick() * 1e6), 0xFFFF)
		for i = 1, CONFIG.NonceLength do
			local randomIndex = bit32.band(bit32.bxor(math.random(1, #chars), entropy + i), 0x3F) % #chars + 1
			result[i] = string.sub(chars, randomIndex, randomIndex)
		end
		return table.concat(result)
	end

	function Utils.Encode(t: { [any]: any }): string
		local parts = {}
		local keys  = {}
		for k in pairs(t) do
			keys[#keys + 1] = tostring(k)
		end
		table.sort(keys)
		for _, k in ipairs(keys) do
			local v = t[k]
			if type(v) == "table" then
				parts[#parts + 1] = k .. "={" .. Utils.Encode(v) .. "}"
			else
				parts[#parts + 1] = k .. "=" .. tostring(v)
			end
		end
		return table.concat(parts, "|")
	end

	function Utils.GenerateSecret(): string
		local a = math.random(0x1000, 0xFFFF)
		local b = math.random(0x1000, 0xFFFF)
		local c = math.floor(tick() * 1000) % 0xFFFF
		return string.format("%04X%04X%04X", a, c, b)
	end

	-- Signal class
	local SignalClass = {}
	SignalClass.__index = SignalClass

	function SignalClass:Connect(callback): ScriptConnection
		assert(type(callback) == "function", "Signal:Connect expects a function")

		self._nextId += 1
		local id   = self._nextId
		local conn = {
			Connected  = true,
			Disconnect = function(s)
				if not s.Connected then return end
				s.Connected      = false
				self._conns[id]     = nil
				self._count         = math.max(0, self._count - 1)
			end,
			_callback  = callback,
		}
		self._conns[id] = conn
		self._count    += 1
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
			if c and c.Connected and type(c._callback) == "function" then
				task.spawn(function()
					local ok, err = pcall(c._callback, table.unpack(args, 1, args.n))
					if not ok then
						Utils.Log("Signal callback error: %s", tostring(err))
					end
				end)
			end
		end
	end

	Framework = {
		Utils = Utils,
		CreateSignal = function(): ScriptSignal
			return setmetatable({
				_conns  = {},
				_count  = 0,
				_nextId = 0,
			}, SignalClass)
		end,
	} :: {
		Utils: typeof(Utils),
		CreateSignal: () -> ScriptSignal,
	}
end

-- Creates the NET folder on the server, or waits for it on the client.
local function makeOrGetFolder(): Folder?
	if IS_SERVER then
		local existing = CONFIG.FolderParent:FindFirstChild(CONFIG.NameDictionary.Folder)
		if existing then return existing :: Folder end

		local folder   = Instance.new("Folder")
		folder.Name    = CONFIG.NameDictionary.Folder
		folder.Parent  = CONFIG.FolderParent
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

-- Creates or retrieves all remote instances under the NET folder. Server creates them; client waits for them.
local function getOrSetupRemotes(): { [string]: RemoteEvent | UnreliableRemoteEvent | RemoteFunction }?
	local folder = makeOrGetFolder()
	if not folder then return nil end

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
			return nil
		end

		return Framework.Utils.MakeDictionaryFromTuple(request, unreliable, reliable, ack)
	end
end

-- Private State
local Remotes  = getOrSetupRemotes()
local ReliableRemote   = Remotes and Remotes[CONFIG.NameDictionary.Reliable]        :: RemoteEvent
local UnreliableRemote = Remotes and Remotes[CONFIG.NameDictionary.UnreliableEvent] :: UnreliableRemoteEvent
local AckRemote        = Remotes and Remotes[CONFIG.NameDictionary.Ack]             :: RemoteEvent
local HandshakeRemote  = Remotes and Remotes[CONFIG.NameDictionary.Request]         :: RemoteFunction

local NET = {
	-- [streamId] = Stream
	Streams = {} :: { [number]: Stream },

	-- [streamId] = ScriptSignal  (fires with (player?, data))
	ReceiveSignals = {} :: { [number]: ScriptSignal },

	-- [nonce] = tick() at reception  (server only)
	SeenNonces = {} :: { [string]: number },

	-- [Player] = Session
	Sessions = {} :: { [Player]: Session },

	-- [Player] = TokenBucket
	TokenBuckets = {} :: { [Player]: TokenBucket },

	-- [Player] = { count, window, violations }
	AnomalyStats = {} :: { [Player]: { count: number, window: number, violations: number } },

	-- [Player] = BandwidthSample
	Bandwidth = {} :: { [Player]: BandwidthSample },

	-- [Player] = DeadReckonSample
	DeadReckon = {} :: { [Player]: DeadReckonSample },

	-- [Player] = { reliable = { Node }, unreliable = { Node } }
	OutgoingQueue = {} :: { [Player]: { reliable: { Node }, unreliable: { Node } } },

	-- [Player] = tick() at last ping send
	PingTimestamps = {} :: { [Player]: number },
	-- [Player] = latest measured RTT in seconds
	RTT = {} :: { [Player]: number },

	-- Set of players whose client has finished handshake and connected all listeners
	ReadyPlayers = {} :: { [Player]: boolean },

	-- [streamId] = { { callback } } — OnReceive calls made before the stream was registered
	PendingReceive = {} :: { [number]: { { callback: (...any) -> () } } },

	ClientSecret = nil :: string?,
	ClientToken  = nil :: string?,
}

-- Internal Helpers

-- Returns the token bucket for a player, creating it if it does not exist.
local function getOrCreateBucket(player: Player): TokenBucket
	if not NET.TokenBuckets[player] then
		NET.TokenBuckets[player] = {
			Tokens     = CONFIG.BucketCapacity,
			LastRefill = tick(),
		}
	end
	return NET.TokenBuckets[player]
end

-- Attempts to consume `cost` tokens from a player's bucket.
local function consumeToken(player: Player, cost: number?): boolean
	local c      = cost or 1
	local bucket = getOrCreateBucket(player)
	local now    = tick()
	local elapsed = now - bucket.LastRefill

	bucket.Tokens     = math.min(CONFIG.BucketCapacity, bucket.Tokens + elapsed * CONFIG.BucketRefillRate)
	bucket.LastRefill = now

	if bucket.Tokens >= c then
		bucket.Tokens -= c
		return true
	end
	return false
end

-- Tracks the incoming packet rate for a player and flags anomalies.
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
			Framework.Utils.Log("Anomaly detected for %s — pps: %d (violation %d/%d)",
				player.Name, stats.count, stats.violations, CONFIG.MaxViolations)

			if stats.violations >= CONFIG.MaxViolations then
				Framework.Utils.Log("Kicking %s for sustained anomalous network behaviour.", player.Name)
				player:Kick("[NET] Suspicious network activity detected.")
			end
		end
		stats.count  = 0
		stats.window = tick()
	end
end

-- Records outgoing bytes for a player and updates the rolling bandwidth estimate.
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

-- Validates that `incomingSeq` falls within the acceptable sliding window
local function isValidSequence(stream: Stream, incomingSeq: number): boolean
	local expected = stream.NextExpected
	if incomingSeq <= expected - CONFIG.StreamWindow then return false end
	if incomingSeq >  expected + CONFIG.StreamWindow then return false end
	return true
end

-- Checks whether a pair has already been seen or has expired
local function isReplay(nonce: string, timestamp: number): boolean
	if NET.SeenNonces[nonce] then return true end
	if math.abs(tick() - timestamp) > CONFIG.NonceExpiry then return true end
	NET.SeenNonces[nonce] = tick()
	return false
end

-- Validates the session token for a player
local function isValidSession(player: Player, token: string): boolean
	local session = NET.Sessions[player]
	if not session then return false end
	if session.Token ~= token then return false end
	if tick() - session.CreatedAt > CONFIG.SessionExpiry then return false end
	session.LastSeen = tick()
	return true
end

-- Verifies the HMAC-style signature on an incoming node.
local function isValidSignature(player: Player, node: Node): boolean
	local session = NET.Sessions[player]
	if not session then return false end

	local sig       = node.Signature
	node.Signature  = ""  -- exclude from hash input
	local expected  = Framework.Utils.Sign(Framework.Utils.Encode(node :: any), session.Secret)
	node.Signature  = sig -- restore

	return sig == expected
end

-- Checks whether the reported position is suspicious
local function isSuspiciousPosition(player: Player, position: Vector3, velocity: Vector3): boolean
	local sample = NET.DeadReckon[player]
	if not sample then
		NET.DeadReckon[player] = {
			LastPosition  = position,
			LastVelocity  = velocity,
			LastTimestamp = tick(),
		}
		return false
	end

	local dt = tick() - sample.LastTimestamp
	local predicted = sample.LastPosition + sample.LastVelocity * dt
	local deviation = (predicted - position).Magnitude

	sample.LastPosition  = position
	sample.LastVelocity  = velocity
	sample.LastTimestamp = tick()

	return deviation > CONFIG.PositionThreshold
end

-- Serialises a Node for signing. 
local function encodeNode(node: Node): string
	local copy = table.clone(node :: any)
	copy.Signature  = nil
	return Framework.Utils.Encode(copy)
end

-- Signs a node using the local session secret (client-side) or a player's session secret (server-side).
local function signNode(node: Node, secret: string): string
	return Framework.Utils.Sign(encodeNode(node), secret)
end

-- Internal constructor for a new Stream with zeroed state.
local function createStream(id: number, reliable: boolean): Stream
	return {
		Id             = id,
		Reliable       = reliable,
		NextExpected   = 0,
		SendSequence   = 0,
		SendBuffer     = {},
		ReceiveBuffer  = {},
	}
end

-- Registers a stream locally without broadcasting (used internally to avoid recursion).
local function registerStreamLocal(identifier: number, reliable: boolean)
	if NET.Streams[identifier] then return end
	NET.Streams[identifier]        = createStream(identifier, reliable)
	NET.ReceiveSignals[identifier] = Framework.CreateSignal()
	Framework.Utils.Log("Registered stream %d (reliable=%s)", identifier, tostring(reliable))
end

-- Processes a fully validated node for a given player.
local function processNode(player: Player?, node: Node)
	local stream = NET.Streams[node.StreamId]
	if not stream then return end

	-- On the client, player is nil — fire only the payload so callbacks receive (data) not (nil, data)
	local function fireSignal(signal, payload)
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
		-- Unreliable streams fire immediately without ordering guarantees
		local signal = NET.ReceiveSignals[node.StreamId]
		fireSignal(signal, node.Payload)
	end
end

-- Runs an incoming node from a client through the full validation pipeline
local function receiveFromClient(player: Player, node: Node)
	if not isValidSession(player, node.Token) then
		Framework.Utils.Log("Invalid session token from %s on stream %d", player.Name, node.StreamId)
		return
	end

	if isReplay(node.Nonce, node.Timestamp) then
		Framework.Utils.Log("Replay or stale node from %s on stream %d", player.Name, node.StreamId)
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
		return
	end

	local cost = CONFIG.StreamCosts[node.StreamId] or 1
	if not consumeToken(player, cost) then
		Framework.Utils.Log("Rate limit exceeded for %s on stream %d", player.Name, node.StreamId)
		return
	end

	trackAnomaly(player)

	if node.Reliable then
		AckRemote:FireClient(player, { StreamId = node.StreamId, AckPosition = node.Position })
	end

	processNode(player, node)
end

-- Processes a node received from the server on the client side.
local function receiveAckFromClient(player: Player, ack: { StreamId: number, AckPosition: number })
	local stream = NET.Streams[ack.StreamId]
	if not stream then return end
	stream.SendBuffer[ack.AckPosition] = nil
end

-- Processes a node received from the server on the client side.
local function receiveFromServer(node: Node)
	local stream = NET.Streams[node.StreamId]
	if not stream then return end

	if node.Reliable then
		-- Send ACK back to server
		AckRemote:FireServer({ StreamId = node.StreamId, AckPosition = node.Position })
	end

	processNode(nil, node)
end

-- Processes an ACK from the server, clearing the entry from the client's send buffer.
local function receiveAckFromServer(ack: { StreamId: number, AckPosition: number })
	local stream = NET.Streams[ack.StreamId]
	if not stream then return end
	stream.SendBuffer[ack.AckPosition] = nil
end

-- Constructs a Node, signs it, and pushes it onto the appropriate outgoing queue.
local function buildAndQueue(streamId: number, payload: { [any]: any }, player: Player?)
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

	-- Sign with the appropriate secret
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

		-- Buffer reliable nodes for potential retransmission
		if stream.Reliable then
			stream.SendBuffer[stream.SendSequence] = {
				Node   = node,
				SentAt = tick(),
				Retries = 0,
			}
		end

		trackBandwidth(player, #Framework.Utils.Encode(node :: any))
	else
		-- Client sends immediately (no batch queue needed for single-player → server direction)
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

-- Flush the outgoing batch queue every Heartbeat (server)
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

-- Retransmit unacknowledged reliable nodes (both sides)
RunService.Heartbeat:Connect(function()
	for _, stream in pairs(NET.Streams) do
		if not stream.Reliable then continue end
		for seq, buffered in pairs(stream.SendBuffer) do
			if tick() - buffered.SentAt >= CONFIG.RetransmitInterval then
				buffered.Retries += 1
				if buffered.Retries > CONFIG.MaxRetries then
					Framework.Utils.Log("Dropping unacknowledged node on stream %d seq %d after %d retries",
						stream.Id, seq, buffered.Retries)
					stream.SendBuffer[seq] = nil
					continue
				end
				buffered.SentAt = tick()
				if IS_SERVER then
					-- Server retransmits to all clients
				else
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

-- Secret rotation: push new secrets to all connected clients (server)
if IS_SERVER then
	task.spawn(function()
		while true do
			task.wait(CONFIG.SecretRotation)
			for player, session in pairs(NET.Sessions) do
				local newSecret    = Framework.Utils.GenerateSecret()
				session.Secret     = newSecret
				ReliableRemote:FireClient(player, { {
					StreamId  = -1,
					Position  = -1,
					AckNumber = -1,
					Reliable  = true,
					Nonce     = Framework.Utils.Nonce(),
					Timestamp = tick(),
					Token     = session.Token,
					Signature = "",
					Payload   = { __type = "SECRET_ROTATION", secret = newSecret },
				} })
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
	-- Handshake: issue session token + secret to connecting client, and replicate all currently registered streams
	if HandshakeRemote then
		HandshakeRemote.OnServerInvoke = function(player: Player): { token: string, secret: string, streams: { { id: number, reliable: boolean } } }
			local token  = Framework.Utils.Nonce() .. Framework.Utils.Nonce()
			local secret = Framework.Utils.GenerateSecret()

			NET.Sessions[player] = {
				Player    = player,
				Token     = token,
				Secret    = secret,
				CreatedAt = tick(),
				LastSeen  = tick(),
			}
			NET.OutgoingQueue[player] = { reliable = {}, unreliable = {} }
			Framework.Utils.Log("Session created for %s — token: %s", player.Name, token)

			-- Collect all currently registered streams to send to the client
			local streamList = {}
			for id, stream in pairs(NET.Streams) do
				streamList[#streamList + 1] = { id = id, reliable = stream.Reliable }
			end

			return { token = token, secret = secret, streams = streamList }
		end
	end

	-- Receive nodes from clients (reliable channel)
	if ReliableRemote then
		ReliableRemote.OnServerEvent:Connect(function(player: Player, node: Node)
			if not node then return end
			-- Handle client ready signal — marks the player's listeners as fully connected
			if node.Payload and node.Payload.__type == "READY" then
				NET.ReadyPlayers[player] = true
				Framework.Utils.Log("%s is ready to receive.", player.Name)
				return
			end
			-- Handle PONG responses
			if node.Payload and node.Payload.__type == "PONG" then
				local sentAt = NET.PingTimestamps[player]
				if sentAt then
					NET.RTT[player] = tick() - sentAt
					NET.PingTimestamps[player] = nil
					Framework.Utils.Log("RTT for %s: %dms", player.Name, math.floor(NET.RTT[player] * 1000))
				end
				return
			end
			receiveFromClient(player, node)
		end)
	end

	-- Receive nodes from clients (unreliable channel)
	if UnreliableRemote then
		UnreliableRemote.OnServerEvent:Connect(function(player: Player, node: Node)
			if not node then return end
			receiveFromClient(player, node)
		end)
	end

	-- Receive ACKs from clients
	if AckRemote then
		AckRemote.OnServerEvent:Connect(function(player: Player, ack)
			if not ack then return end
			receiveAckFromClient(player, ack)
		end)
	end

	-- Clean up on player leave
	game:GetService("Players").PlayerRemoving:Connect(function(player: Player)
		NET.Sessions[player]       = nil
		NET.TokenBuckets[player]   = nil
		NET.AnomalyStats[player]   = nil
		NET.Bandwidth[player]      = nil
		NET.DeadReckon[player]     = nil
		NET.OutgoingQueue[player]  = nil
		NET.PingTimestamps[player] = nil
		NET.RTT[player]            = nil
		NET.ReadyPlayers[player]   = nil
		Framework.Utils.Log("Cleaned up state for %s", player.Name)
	end)

else
	-- CLIENT: perform handshake to obtain session token + secret, then register all replicated streams
	if HandshakeRemote then
		task.spawn(function()
			local result = HandshakeRemote:InvokeServer()
			if result then
				NET.ClientToken  = result.token
				NET.ClientSecret = result.secret
				Framework.Utils.Log("Handshake complete — token: %s", result.token)
				-- Replicate streams the server already had registered at handshake time
				if result.streams then
					for _, entry in ipairs(result.streams) do
						registerStreamLocal(entry.id, entry.reliable)
					end
				end
				-- Signal to the server that all listeners are connected and the client is ready to receive
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
			end
		end)
	end

	-- Receive batched node arrays from server (reliable channel)
	if ReliableRemote then
		ReliableRemote.OnClientEvent:Connect(function(nodes: { Node })
			if type(nodes) ~= "table" then return end
			for _, node in ipairs(nodes) do
				if node.Payload and node.Payload.__type == "SECRET_ROTATION" then
					NET.ClientSecret = node.Payload.secret
					Framework.Utils.Log("Secret rotated by server.")
				elseif node.Payload and node.Payload.__type == "PING" then
					-- Respond immediately with a PONG
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
					-- Server is replicating a newly registered stream to this client
					registerStreamLocal(node.Payload.id, node.Payload.reliable)
				else
					receiveFromServer(node)
				end
			end
		end)
	end

	-- Receive batched node arrays from server (unreliable channel)
	if UnreliableRemote then
		UnreliableRemote.OnClientEvent:Connect(function(nodes: { Node })
			if type(nodes) ~= "table" then return end
			for _, node in ipairs(nodes) do
				receiveFromServer(node)
			end
		end)
	end

	-- Receive ACKs from server
	if AckRemote then
		AckRemote.OnClientEvent:Connect(function(ack)
			if not ack then return end
			receiveAckFromServer(ack)
		end)
	end
end

-- Public API
local NETPublic = {}
NETPublic.__index = NETPublic

--[[
Registers a new stream on this peer.
Must be called on both server and client with matching arguments before
any nodes are sent or received on that stream.

@param identifier: number   - Unique stream ID (e.g. 1, 2, 3)
@param reliable:   boolean  - true = Transmission Control Protocol (TCP); false = User Datagram Protocol (UDP)
]]
function NETPublic:RegisterStream(identifier: number, reliable: boolean)
	assert(type(identifier) == "number", "RegisterStream: identifier must be a number")
	assert(type(reliable)   == "boolean", "RegisterStream: reliable must be a boolean")

	if NET.Streams[identifier] then
		Framework.Utils.Log("Stream %d is already registered, skipping.", identifier)
		return
	end

	registerStreamLocal(identifier, reliable)

	-- Replicate the new stream to all currently connected clients (server only)
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
Sends a payload on the given stream.

Server usage: NET:Send(player, streamId, payload)
Client usage: NET:Send(streamId, payload)

@param ...  - See above overloads
]]
function NETPublic:Send(...): ()
	local args = { ... }
	if IS_SERVER then
		local player:   Player           = args[1]
		local streamId: number           = args[2]
		local payload:  { [any]: any }   = args[3]
		assert(typeof(player)   == "Instance", "Send (server): first argument must be a Player")
		assert(type(streamId)   == "number",   "Send (server): second argument must be a stream ID")
		assert(type(payload)    == "table",    "Send (server): third argument must be a table")
		buildAndQueue(streamId, payload, player)
	else
		local streamId: number           = args[1]
		local payload:  { [any]: any }   = args[2]
		assert(type(streamId) == "number", "Send (client): first argument must be a stream ID")
		assert(type(payload)  == "table",  "Send (client): second argument must be a table")
		buildAndQueue(streamId, payload, nil)
	end
end

--[[
Registers a callback to fire when a node is received on the given stream.

Server callback: function(player: Player, data: {[any]: any})
Client callback: function(data: {[any]: any})

@param streamId: number          - The stream to listen on
@param callback: (...any) -> ()  - Called with (player?, payload)
@returns ScriptConnection
]]
function NETPublic.OnReceive(streamId: number, callback: (...any) -> ()): ScriptConnection
	assert(NET.ReceiveSignals[streamId], "OnReceive: stream " .. tostring(streamId) .. " is not registered")
	return NET.ReceiveSignals[streamId]:Connect(callback)
end

--[[
Returns the most recently measured round-trip time for a player in seconds.
SERVER ONLY — returns nil if no measurement has been taken yet.

@param player: Player
@returns number?  - RTT in seconds, or nil
]]
function NETPublic:GetRTT(player: Player): number?
	assert(IS_SERVER, "GetRTT is only available on the server")
	return NET.RTT[player]
end

--[[
Returns the estimated outgoing bandwidth to a player in bytes per second.
SERVER ONLY.

@param player: Player
@returns number  - Estimated bytes/sec (0 if no data yet)
]]
function NETPublic:GetBandwidth(player: Player): number
	assert(IS_SERVER, "GetBandwidth is only available on the server")
	local sample = NET.Bandwidth[player]
	return sample and sample.EstimatedBps or 0
end

--[[
Validates a reported movement position using dead reckoning.
Returns true if the position appears suspicious (too far from predicted location).
SERVER ONLY.

@param player:   Player
@param position: Vector3  - Reported position
@param velocity: Vector3  - Reported velocity
@returns boolean
]]
function NETPublic:IsSuspiciousPosition(player: Player, position: Vector3, velocity: Vector3): boolean
	assert(IS_SERVER, "IsSuspiciousPosition is only available on the server")
	return isSuspiciousPosition(player, position, velocity)
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

-- We are done!

setmetatable(NET, {
	__index = function(_, k)
		local method = NETPublic[k]
		if method then return method end
		if rawget(NET, k) ~= nil then return rawget(NET, k) end
		error(("Attempt to index NET with unknown key '%s'"):format(tostring(k)), 2)
	end,
	__tostring = function()
		return "NET"
	end,
	__metatable = "LockedMeta",
})

return NET :: typeof(NETPublic)
