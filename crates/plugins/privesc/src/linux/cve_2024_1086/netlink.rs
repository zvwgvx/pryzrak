//! Low-level Netlink socket wrapper and message primitives

use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// Netlink protocol constants
pub const NETLINK_NETFILTER: i32 = 12;
pub const NFNETLINK_V0: u8 = 0;

// Message flags
pub const NLM_F_REQUEST: u16 = 0x0001;
pub const NLM_F_MULTI: u16 = 0x0002;
pub const NLM_F_ACK: u16 = 0x0004;
pub const NLM_F_ECHO: u16 = 0x0008;
pub const NLM_F_DUMP_INTR: u16 = 0x0010;
pub const NLM_F_DUMP_FILTERED: u16 = 0x0020;

// For NEW/DEL
pub const NLM_F_ROOT: u16 = 0x0100;
pub const NLM_F_MATCH: u16 = 0x0200;
pub const NLM_F_ATOMIC: u16 = 0x0400;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

// For NEW
pub const NLM_F_REPLACE: u16 = 0x0100;
pub const NLM_F_EXCL: u16 = 0x0200;
pub const NLM_F_CREATE: u16 = 0x0400;
pub const NLM_F_APPEND: u16 = 0x0800;

// Netlink header
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

// Netfilter generic message header
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NfGenMsg {
    pub nfgen_family: u8,
    pub version: u8,
    pub res_id: u16,
}

// Netlink attribute header
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NlAttr {
    pub nla_len: u16,
    pub nla_type: u16,
}

// Socket address for Netlink
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockaddrNl {
    pub nl_family: u16,
    pub nl_pad: u16,
    pub nl_pid: u32,
    pub nl_groups: u32,
}

impl Default for SockaddrNl {
    fn default() -> Self {
        Self {
            nl_family: libc::AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        }
    }
}

/// Low-level Netlink socket wrapper
pub struct NetlinkSocket {
    fd: OwnedFd,
    seq: u32,
    pid: u32,
}

impl NetlinkSocket {
    pub fn new() -> Result<Self, String> {
        let fd = unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_NETFILTER)
        };

        if fd < 0 {
            return Err(format!("socket() failed: {}", std::io::Error::last_os_error()));
        }

        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let pid = std::process::id();

        // Bind to kernel
        let mut addr = SockaddrNl::default();
        addr.nl_pid = pid;

        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                size_of::<SockaddrNl>() as u32,
            )
        };

        if ret < 0 {
            return Err(format!("bind() failed: {}", std::io::Error::last_os_error()));
        }

        // Set socket buffer sizes for reliability
        let bufsize: i32 = 1024 * 1024; // 1MB
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &bufsize as *const _ as *const libc::c_void,
                size_of::<i32>() as u32,
            );
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &bufsize as *const _ as *const libc::c_void,
                size_of::<i32>() as u32,
            );
        }

        Ok(Self { fd, seq: 1, pid })
    }

    pub fn fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    pub fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq += 1;
        s
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Send raw bytes to kernel
    pub fn send(&self, data: &[u8]) -> Result<usize, String> {
        let addr = SockaddrNl::default();
        
        let iov = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };

        let msg = libc::msghdr {
            msg_name: &addr as *const _ as *mut libc::c_void,
            msg_namelen: size_of::<SockaddrNl>() as u32,
            msg_iov: &iov as *const _ as *mut libc::iovec,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let sent = unsafe { libc::sendmsg(self.fd.as_raw_fd(), &msg, 0) };

        if sent < 0 {
            Err(format!("sendmsg() failed: {}", std::io::Error::last_os_error()))
        } else {
            Ok(sent as usize)
        }
    }

    /// Receive response from kernel
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut addr = SockaddrNl::default();
        
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };

        let mut msg = libc::msghdr {
            msg_name: &mut addr as *mut _ as *mut libc::c_void,
            msg_namelen: size_of::<SockaddrNl>() as u32,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, 0) };

        if n < 0 {
            Err(format!("recvmsg() failed: {}", std::io::Error::last_os_error()))
        } else {
            Ok(n as usize)
        }
    }
}

/// Message builder for constructing Netlink messages
pub struct MessageBuilder {
    buf: Vec<u8>,
    msg_start: usize,
}

impl MessageBuilder {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(4096),
            msg_start: 0,
        }
    }

    pub fn begin_message(&mut self, msg_type: u16, flags: u16, seq: u32, pid: u32) {
        self.msg_start = self.buf.len();

        // Reserve space for header
        let hdr = NlMsgHdr {
            nlmsg_len: 0, // Will be fixed up
            nlmsg_type: msg_type,
            nlmsg_flags: flags,
            nlmsg_seq: seq,
            nlmsg_pid: pid,
        };

        self.buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, size_of::<NlMsgHdr>())
        });
    }

    pub fn add_nfgen_header(&mut self, family: u8) {
        let gen = NfGenMsg {
            nfgen_family: family,
            version: NFNETLINK_V0,
            res_id: 0,
        };

        self.buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&gen as *const _ as *const u8, size_of::<NfGenMsg>())
        });
    }

    pub fn add_attr(&mut self, attr_type: u16, data: &[u8]) {
        let len = (size_of::<NlAttr>() + data.len()) as u16;
        let attr = NlAttr {
            nla_len: len,
            nla_type: attr_type,
        };

        self.buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&attr as *const _ as *const u8, size_of::<NlAttr>())
        });
        self.buf.extend_from_slice(data);

        // Align to 4 bytes
        let padding = (4 - (data.len() % 4)) % 4;
        self.buf.extend(std::iter::repeat(0u8).take(padding));
    }

    pub fn add_attr_string(&mut self, attr_type: u16, s: &str) {
        let mut data = s.as_bytes().to_vec();
        data.push(0); // null terminator
        self.add_attr(attr_type, &data);
    }

    pub fn add_attr_u32(&mut self, attr_type: u16, val: u32) {
        self.add_attr(attr_type, &val.to_ne_bytes());
    }

    pub fn add_attr_u64(&mut self, attr_type: u16, val: u64) {
        self.add_attr(attr_type, &val.to_ne_bytes());
    }

    /// Begin a nested attribute
    pub fn begin_nested(&mut self, attr_type: u16) -> usize {
        let pos = self.buf.len();
        // Placeholder header
        let attr = NlAttr {
            nla_len: 0,
            nla_type: attr_type | (1 << 15), // NLA_F_NESTED
        };
        self.buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&attr as *const _ as *const u8, size_of::<NlAttr>())
        });
        pos
    }

    /// End a nested attribute, fixing up its length
    pub fn end_nested(&mut self, start: usize) {
        let len = (self.buf.len() - start) as u16;
        let len_bytes = len.to_ne_bytes();
        self.buf[start..start + 2].copy_from_slice(&len_bytes);
    }

    /// Finalize message, fixing up length
    pub fn end_message(&mut self) {
        let len = (self.buf.len() - self.msg_start) as u32;
        let len_bytes = len.to_ne_bytes();
        self.buf[self.msg_start..self.msg_start + 4].copy_from_slice(&len_bytes);
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}
