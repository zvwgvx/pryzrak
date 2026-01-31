//! # SYN Scanner
//!
//! Raw socket SYN scanner for discovering vulnerable hosts.
//!
//! ## C Reference: modules/network/scanner/scanner.c (163 lines)

const std = @import("std");
const posix = std.posix;
const crypto = @import("../crypto/mod.zig");

// ============================================================
// CONSTANTS (from C: scanner.c lines 24-25)
// ============================================================

const SCANNER_MAX_PPS: u32 = 1000;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_RAW: u8 = 255;

// ============================================================
// STATE
// ============================================================

var raw_sock: posix.socket_t = -1;
var target_port: u16 = 23; // Telnet default

// ============================================================
// IP HEADER (same as syn.zig)
// ============================================================

const IpHeader = packed struct {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
};

// ============================================================
// TCP HEADER
// ============================================================

const TcpHeader = packed struct {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
};

// ============================================================
// SCANNER INIT (from C: scanner.c scanner_init lines 50-69)
// ============================================================

pub fn init() bool {
    // Create raw socket (requires root)
    raw_sock = posix.socket(posix.AF.INET, posix.SOCK.RAW, IPPROTO_TCP) catch return false;

    // IP_HDRINCL
    const one: i32 = 1;
    const IP_HDRINCL = 3;
    posix.setsockopt(raw_sock, posix.IPPROTO.IP, IP_HDRINCL, std.mem.asBytes(&one)) catch {
        posix.close(raw_sock);
        return false;
    };

    return true;
}

// ============================================================
// GET RANDOM IP (from C: scanner.c get_random_ip lines 71-87)
// ============================================================
// Skip private/loopback ranges

fn getRandomIp(rng: *crypto.FastRandom) u32 {
    while (true) {
        const ip = rng.next();

        // Skip 127.x.x.x (Loopback)
        if ((ip & 0xFF) == 127) continue;
        // Skip 10.x.x.x (Private)
        if ((ip & 0xFF) == 10) continue;
        // Skip 192.168.x.x (Private)
        if ((ip & 0xFFFF) == 0xA8C0) continue;
        // Skip 172.16.x.x-172.31.x.x (Private)
        if ((ip & 0xFF) == 172 and ((ip >> 8) & 0xF0) == 16) continue;

        return ip;
    }
}

// ============================================================
// SCANNER RUN BATCH (from C: scanner.c scanner_run_batch lines 89-157)
// ============================================================

pub fn runBatch() void {
    if (raw_sock < 0) return;

    var rng = crypto.FastRandom.init(@truncate(@as(u64, @bitCast(std.time.timestamp()))));

    // Random destination and source (spoofed)
    const dest_ip = std.mem.nativeToBig(u32, getRandomIp(&rng));
    const source_ip = std.mem.nativeToBig(u32, getRandomIp(&rng));

    var packet: [60]u8 = undefined; // IP (20) + TCP (20) + padding
    @memset(&packet, 0);

    // IP Header (from C: lines 111-124)
    const iph = @as(*IpHeader, @ptrCast(@alignCast(&packet)));
    iph.version_ihl = 0x45; // IPv4, IHL=5
    iph.tos = 0;
    iph.tot_len = std.mem.nativeToBig(u16, 40);
    iph.id = std.mem.nativeToBig(u16, @truncate(rng.next()));
    iph.frag_off = 0;
    iph.ttl = 255;
    iph.protocol = IPPROTO_TCP;
    iph.check = 0;
    iph.saddr = source_ip;
    iph.daddr = dest_ip;

    // IP checksum
    iph.check = crypto.internetChecksum(packet[0..20]);

    // TCP Header (from C: lines 127-135)
    const tcph = @as(*TcpHeader, @ptrCast(@alignCast(packet[20..].ptr)));
    tcph.source = std.mem.nativeToBig(u16, 12345);
    tcph.dest = std.mem.nativeToBig(u16, target_port);
    tcph.seq = 0;
    tcph.ack_seq = 0;
    tcph.doff_flags = std.mem.nativeToBig(u16, 0x5002); // doff=5, SYN flag
    tcph.window = std.mem.nativeToBig(u16, 5840);
    tcph.check = 0;
    tcph.urg_ptr = 0;

    // TCP checksum with pseudo header (from C: lines 138-149)
    tcph.check = calculateTcpChecksum(source_ip, dest_ip, packet[20..40]);

    // Send (from C: lines 152-157)
    var dest: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = dest_ip,
    };

    _ = posix.sendto(raw_sock, packet[0..40], 0, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch {};
}

// ============================================================
// SCANNER INFO (from C: scanner.c scanner_info lines 160-162)
// ============================================================

pub fn info() void {
    if (raw_sock >= 0) {
        posix.close(raw_sock);
        raw_sock = -1;
    }
}

// ============================================================
// TCP CHECKSUM (same as syn.zig)
// ============================================================

fn calculateTcpChecksum(saddr: u32, daddr: u32, tcp_segment: []const u8) u16 {
    var sum: u32 = 0;

    // Pseudo header
    sum += (saddr >> 16) & 0xFFFF;
    sum += saddr & 0xFFFF;
    sum += (daddr >> 16) & 0xFFFF;
    sum += daddr & 0xFFFF;
    sum += IPPROTO_TCP;
    sum += @as(u16, @intCast(tcp_segment.len));

    // TCP segment
    var i: usize = 0;
    while (i + 1 < tcp_segment.len) : (i += 2) {
        sum += @as(u16, tcp_segment[i]) << 8 | tcp_segment[i + 1];
    }
    if (i < tcp_segment.len) {
        sum += @as(u16, tcp_segment[i]) << 8;
    }

    // Fold
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~@as(u16, @truncate(sum));
}
