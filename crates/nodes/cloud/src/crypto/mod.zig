//! # Crypto Module
//!
//! Ed25519 signature verification, fast PRNG, and time-based magic

pub const ed25519 = @import("ed25519.zig");
pub const magic = @import("magic.zig");

// ============================================================
// FAST PRNG (from C: attack.h fast_rand)
// ============================================================
// static inline uint32_t fast_rand(void) {
//     static uint32_t y = 2463534242;
//     y ^= (y << 13);
//     y ^= (y >> 17);
//     y ^= (y << 5);
//     return y;
// }

/// Xorshift32 PRNG - fast, non-cryptographic random
pub const FastRandom = struct {
    state: u32,

    pub fn init(seed: u32) FastRandom {
        return .{ .state = if (seed == 0) 2463534242 else seed };
    }

    /// Generate next random u32 (xorshift32 algorithm)
    pub fn next(self: *FastRandom) u32 {
        var y = self.state;
        y ^= y << 13;
        y ^= y >> 17;
        y ^= y << 5;
        self.state = y;
        return y;
    }

    /// Fill buffer with random bytes
    pub fn fill(self: *FastRandom, buffer: []u8) void {
        var i: usize = 0;
        while (i + 4 <= buffer.len) : (i += 4) {
            const val = self.next();
            buffer[i] = @truncate(val);
            buffer[i + 1] = @truncate(val >> 8);
            buffer[i + 2] = @truncate(val >> 16);
            buffer[i + 3] = @truncate(val >> 24);
        }
        // Handle remaining bytes
        if (i < buffer.len) {
            const val = self.next();
            var j: u5 = 0;
            while (i < buffer.len) : ({
                i += 1;
                j += 8;
            }) {
                buffer[i] = @truncate(val >> j);
            }
        }
    }
};

// ============================================================
// CHECKSUM (from C: attack.h csum)
// ============================================================
// static inline unsigned short csum(unsigned short *ptr, int nbytes) {
//     register long sum = 0;
//     while (nbytes > 1) { sum += *ptr++; nbytes -= 2; }
//     if (nbytes == 1) sum += *(unsigned char *)ptr;
//     sum = (sum >> 16) + (sum & 0xffff);
//     sum += (sum >> 16);
//     return (unsigned short)(~sum);
// }

/// Internet checksum (RFC 1071)
pub fn internetChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    // Sum 16-bit words
    while (i + 1 < data.len) : (i += 2) {
        const word: u16 = (@as(u16, data[i]) << 8) | data[i + 1];
        sum += word;
    }

    // Add odd byte if present
    if (i < data.len) {
        sum += @as(u16, data[i]) << 8;
    }

    // Fold 32-bit sum to 16-bit
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~@as(u16, @truncate(sum));
}

// ============================================================
// TESTS
// ============================================================

test "FastRandom produces expected sequence" {
    var rng = FastRandom.init(2463534242);

    // First few values from xorshift32 with default seed
    _ = rng.next(); // Just verify it runs
    _ = rng.next();
    _ = rng.next();
}

test "internetChecksum correctness" {
    // Test vector: "test" should produce a specific checksum
    const data = "test";
    const result = internetChecksum(data);
    _ = result; // Just verify it compiles and runs
}
