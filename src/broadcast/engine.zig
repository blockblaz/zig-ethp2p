//! Broadcast engine: owns channels keyed by id (aligned with ethp2p `broadcast/engine.go`).

const std = @import("std");
const ChannelRs = @import("channel_rs.zig").ChannelRs;
const dedup_registry_mod = @import("../layer/dedup_registry.zig");
const observer_mod = @import("observer.zig");

const Allocator = std.mem.Allocator;

pub const EngineConfig = struct {
    observer: observer_mod.Observer = .{},
    /// When set, `Engine` owns a `DedupRegistry` for `relayIngestChunk`-style helpers.
    enable_cross_session_dedup: bool = false,
};

pub const Engine = struct {
    allocator: Allocator,
    local_peer_id: []u8,
    config: EngineConfig,
    channels: std.StringHashMapUnmanaged(*ChannelRs),
    dedup_registry: ?dedup_registry_mod.DedupRegistry = null,

    pub fn init(allocator: Allocator, local_peer_id: []const u8, config: EngineConfig) !Engine {
        var dedup_registry: ?dedup_registry_mod.DedupRegistry = null;
        if (config.enable_cross_session_dedup) {
            dedup_registry = dedup_registry_mod.DedupRegistry{};
        }
        return .{
            .allocator = allocator,
            .local_peer_id = try allocator.dupe(u8, local_peer_id),
            .config = config,
            .channels = .{},
            .dedup_registry = dedup_registry,
        };
    }

    pub fn deinit(self: *Engine) void {
        var it = self.channels.iterator();
        while (it.next()) |kv| {
            const ch = kv.value_ptr.*;
            ch.deinit();
            self.allocator.destroy(ch);
        }
        self.channels.deinit(self.allocator);
        if (self.dedup_registry) |*d| {
            d.deinit(self.allocator);
        }
        self.allocator.free(self.local_peer_id);
    }

    pub fn dedupRegistryPtr(self: *Engine) ?*dedup_registry_mod.DedupRegistry {
        if (self.dedup_registry) |*d| return d;
        return null;
    }

    pub fn attachChannelRs(
        self: *Engine,
        channel_id: []const u8,
        cfg: @import("../layer/rs_init.zig").RsConfig,
    ) !*ChannelRs {
        if (self.channels.get(channel_id) != null) return error.ChannelExists;
        const key = try self.allocator.dupe(u8, channel_id);
        errdefer self.allocator.free(key);
        const ch = try self.allocator.create(ChannelRs);
        errdefer self.allocator.destroy(ch);
        ch.* = try ChannelRs.init(self.allocator, self, key, cfg);
        try self.channels.put(self.allocator, key, ch);
        return ch;
    }
};

pub const Error = error{ChannelExists};
