//! # MQTT-style Proxy
//!
//! TCP server that accepts Edge node connections and broadcasts commands.
//!
//! ## C Reference: modules/network/proxy/proxy.c (144 lines)

const std = @import("std");
const posix = std.posix;
const protocol = @import("../protocol.zig");

// ============================================================
// CONSTANTS (from C: proxy.h lines 8-10)
// ============================================================

pub const PROXY_LISTEN_PORT: u16 = 1883;
pub const MAX_SUBSCRIBERS: usize = 5;

// ============================================================
// SUBSCRIBER (from C: proxy.h lines 12-16)
// ============================================================
// typedef struct {
//     int fd;
//     bool active;
//     time_t last_heartbeat;
// } Subscriber;

pub const Subscriber = struct {
    fd: posix.socket_t,
    active: bool,
    last_heartbeat: i64,
};

// ============================================================
// PROXY STATE
// ============================================================

pub const Proxy = struct {
    sock: posix.socket_t,
    subscribers: [MAX_SUBSCRIBERS]Subscriber,

    // ============================================================
    // INIT (from C: proxy.c proxy_init lines 21-56)
    // ============================================================

    pub fn init() !Proxy {
        const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
        errdefer posix.close(sock);

        // SO_REUSEADDR
        const opt: i32 = 1;
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&opt)) catch {};

        // Bind
        var addr: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, PROXY_LISTEN_PORT),
            .addr = 0, // INADDR_ANY
        };

        try posix.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
        try posix.listen(sock, 1024);

        // Non-blocking
        const flags = try posix.fcntl(sock, posix.F.GETFL, 0);
        _ = try posix.fcntl(sock, posix.F.SETFL, flags | @as(u32, @bitCast(posix.O{ .NONBLOCK = true })));

        var self = Proxy{
            .sock = sock,
            .subscribers = undefined,
        };

        // Init subscribers
        for (&self.subscribers) |*s| {
            s.fd = -1;
            s.active = false;
            s.last_heartbeat = 0;
        }

        return self;
    }

    pub fn deinit(self: *Proxy) void {
        for (self.subscribers) |s| {
            if (s.active) {
                posix.close(s.fd);
            }
        }
        posix.close(self.sock);
    }

    // ============================================================
    // HANDLE NEW CONN (from C: proxy.c proxy_handle_new_conn lines 58-85)
    // ============================================================

    pub fn handleNewConnection(self: *Proxy) void {
        var client_addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

        const client_sock = posix.accept(self.sock, @ptrCast(&client_addr), &addr_len, 0) catch return;

        // Set non-blocking
        const flags = posix.fcntl(client_sock, posix.F.GETFL, 0) catch {
            posix.close(client_sock);
            return;
        };
        _ = posix.fcntl(client_sock, posix.F.SETFL, flags | @as(u32, @bitCast(posix.O{ .NONBLOCK = true }))) catch {
            posix.close(client_sock);
            return;
        };

        // Add to subscriber list
        var added = false;
        for (&self.subscribers) |*s| {
            if (!s.active) {
                s.fd = client_sock;
                s.active = true;
                s.last_heartbeat = std.time.timestamp();
                added = true;
                break;
            }
        }

        if (!added) {
            posix.close(client_sock);
        }
    }

    // ============================================================
    // BROADCAST (from C: proxy.c proxy_broadcast lines 99-138)
    // ============================================================

    pub fn broadcast(self: *Proxy, payload: []const u8) void {
        // Construct MQTT PUBLISH packet
        // [0x30] [Remaining Len] [Topic Len] [Topic] [Payload]
        const topic = "cmd/broadcast";
        const topic_len = topic.len;

        var header: [128]u8 = undefined;

        header[0] = protocol.WIRE_MQTT_PUBLISH; // 0x30 - PUBLISH, QoS 0

        // Remaining length = 2 (topic len) + topic + payload
        const rem_len = 2 + topic_len + payload.len;
        const var_len_bytes = encodeVarLength(rem_len, header[1..5]);

        // Send to all subscribers
        for (&self.subscribers) |*s| {
            if (s.active) {
                // Write header
                _ = posix.send(s.fd, header[0 .. 1 + var_len_bytes], posix.MSG.NOSIGNAL) catch {};

                // Write topic length (big endian)
                var tlen_be: [2]u8 = undefined;
                std.mem.writeInt(u16, &tlen_be, @intCast(topic_len), .big);
                _ = posix.send(s.fd, &tlen_be, posix.MSG.NOSIGNAL) catch {};

                // Write topic
                _ = posix.send(s.fd, topic, posix.MSG.NOSIGNAL) catch {};

                // Write payload
                _ = posix.send(s.fd, payload, posix.MSG.NOSIGNAL) catch {
                    // Error, disconnect
                    posix.close(s.fd);
                    s.active = false;
                };
            }
        }
    }

    pub fn getSocket(self: *Proxy) posix.socket_t {
        return self.sock;
    }
};

// ============================================================
// HELPER: Encode MQTT Variable Length (from C: proxy.c lines 88-97)
// ============================================================

fn encodeVarLength(len: usize, buf: []u8) usize {
    var remaining = len;
    var i: usize = 0;

    while (true) {
        var byte: u8 = @truncate(remaining % 128);
        remaining /= 128;
        if (remaining > 0) {
            byte |= 128;
        }
        buf[i] = byte;
        i += 1;
        if (remaining == 0) break;
    }

    return i;
}
