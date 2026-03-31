//! Broadcast engine: owns channels keyed by id (aligned with ethp2p `broadcast/engine.go`).

const std = @import("std");
const ChannelRs = @import("channel_rs.zig").ChannelRs;
const observer_mod = @import("observer.zig");

const Allocator = std.mem.Allocator;

pub const EngineConfig = struct {
    observer: observer_mod.Observer = .{},
};

pub const Engine = struct {
    allocator: Allocator,
    local_peer_id: []u8,
    config: EngineConfig,
    channels: std.StringHashMapUnmanaged(*ChannelRs),

    pub fn init(allocator: Allocator, local_peer_id: []const u8, config: EngineConfig) !Engine {
        return .{
            .allocator = allocator,
            .local_peer_id = try allocator.dupe(u8, local_peer_id),
            .config = config,
            .channels = .{},
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
        self.allocator.free(self.local_peer_id);
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
