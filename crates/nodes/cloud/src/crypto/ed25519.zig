//! # Ed25519 Signature Verification
//!
//! Uses Zig std.crypto instead of TweetNaCl
//!
//! ## C Reference: modules/crypto/verify.c, tweetnacl.c

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

// ============================================================
// MASTER PUBLIC KEY (from C: verify.c)
// ============================================================
// In production, this would be embedded at compile time or loaded securely

/// Master public key (32 bytes) - replace with actual key
pub const MASTER_PUBLIC_KEY: [32]u8 = .{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// ============================================================
// SIGNATURE VERIFICATION (from C: verify.c ed25519_verify)
// ============================================================
// int ed25519_verify(const uint8_t *message, size_t message_len, const uint8_t *signature) {
//     return crypto_sign_verify_detached(signature, message, message_len, master_pubkey) == 0;
// }

/// Verify an Ed25519 signature against the master public key
pub fn verify(message: []const u8, signature: *const [64]u8) bool {
    const sig = Ed25519.Signature.fromBytes(signature.*);
    const public_key = Ed25519.PublicKey.fromBytes(MASTER_PUBLIC_KEY) catch return false;
    
    sig.verify(message, public_key) catch return false;
    return true;
}

/// Verify with a specific public key (for testing or multi-master)
pub fn verifyWithKey(message: []const u8, signature: *const [64]u8, public_key_bytes: *const [32]u8) bool {
    const sig = Ed25519.Signature.fromBytes(signature.*);
    const public_key = Ed25519.PublicKey.fromBytes(public_key_bytes.*) catch return false;
    
    sig.verify(message, public_key) catch return false;
    return true;
}

// ============================================================
// TESTS
// ============================================================

test "verify returns false for invalid signature" {
    const message = "test message";
    var bad_sig: [64]u8 = undefined;
    @memset(&bad_sig, 0);
    
    try std.testing.expect(!verify(message, &bad_sig));
}
