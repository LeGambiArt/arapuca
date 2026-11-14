//! Seccomp user notification (unotify) infrastructure.
//!
//! Provides syscall interception via `SECCOMP_RET_USER_NOTIF` for audit
//! purposes. A supervisor child process receives notifications when the
//! sandboxed process makes intercepted syscalls, reads arguments from
//! `/proc/<pid>/mem`, emits NDJSON audit events, and either allows the
//! syscall through (observation) or blocks it (network enforcement).
//!
//! The supervisor is forked BEFORE any seccomp filters are installed
//! (to avoid inheriting the USER_NOTIF filter, which would deadlock
//! on the supervisor's own `openat` calls). The listener FD number is
//! sent via `write()` on a socketpair; the supervisor duplicates it
//! via `pidfd_getfd`. This avoids `sendmsg` (SCM_RIGHTS) which would
//! be intercepted by the USER_NOTIF filter.
//!
//! Requires kernel ≥ 5.5 (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`).

use std::os::unix::io::RawFd;
use std::sync::OnceLock;

use crate::Error;

// ─── IOCTL constants ──────────────────────────────────────────────
//
// Not in libc 0.2.186. Computed from the kernel's _IOWR/_IOR macros:
//   _IOC(dir, type, nr, size) = (dir << 30) | (type << 8) | nr | (size << 16)
//   type = '!' = 0x21
//
// struct seccomp_notif:      size = 80 bytes (u64 + u32 + u32 + seccomp_data(64))
// struct seccomp_notif_resp: size = 24 bytes (u64 + i64 + i32 + u32)
// u64:                       size = 8 bytes

const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;
const IOC_TYPE: u32 = b'!' as u32;

const fn ioc(dir: u32, nr: u32, size: u32) -> libc::Ioctl {
    ((dir << 30) | (IOC_TYPE << 8) | nr | (size << 16)) as libc::Ioctl
}

/// `ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &notif)` — receive a notification.
const SECCOMP_IOCTL_NOTIF_RECV: libc::Ioctl = ioc(IOC_WRITE | IOC_READ, 0, 80);

/// `ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp)` — send a response.
const SECCOMP_IOCTL_NOTIF_SEND: libc::Ioctl = ioc(IOC_WRITE | IOC_READ, 1, 24);

/// `ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id)` — check if notification is still valid.
/// Kernel 5.17+ uses `_IOW`; kernels 5.0–5.16 use `_IOR`. The 5.17+
/// kernel accepts both, so we try the new one first and fall back.
const SECCOMP_IOCTL_NOTIF_ID_VALID_NEW: libc::Ioctl = ioc(IOC_WRITE, 2, 8);
const SECCOMP_IOCTL_NOTIF_ID_VALID_OLD: libc::Ioctl = ioc(IOC_READ, 2, 8);

// ─── BPF construction ─────────────────────────────────────────────

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc00000b7; // AUDIT_ARCH_AARCH64

const fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Build a raw BPF program that returns `SECCOMP_RET_USER_NOTIF` for
/// the specified syscalls and `SECCOMP_RET_ALLOW` for all others.
///
/// The program structure:
/// 1. Load arch, verify it matches
/// 2. Load syscall number
/// 3. Linear scan: for each target syscall, compare and return USER_NOTIF
/// 4. Default: return ALLOW
pub fn build_unotify_bpf(syscalls: &[i64]) -> crate::Result<Vec<libc::sock_filter>> {
    if syscalls.len() > 127 {
        return Err(Error::Seccomp(format!(
            "unotify BPF: too many syscalls ({}, max 127)",
            syscalls.len()
        )));
    }
    let mut prog = Vec::with_capacity(4 + syscalls.len() * 2 + 1);

    // Load seccomp_data.arch (offset 4)
    prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 4));
    // Check arch matches — skip 1 instruction if match, else jump to ALLOW
    let allow_offset = (syscalls.len() * 2) as u8;
    prog.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH,
        0,
        allow_offset + 1,
    ));

    // Load seccomp_data.nr (offset 0)
    prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0));

    // For each syscall: compare and return USER_NOTIF
    for (i, &nr) in syscalls.iter().enumerate() {
        let remaining = (syscalls.len() - i - 1) as u8;
        // If match: jump to the next instruction (USER_NOTIF return)
        // If no match: skip the USER_NOTIF return
        prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1));
        // Return USER_NOTIF
        prog.push(bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_USER_NOTIF));
        let _ = remaining; // used for documentation clarity
    }

    // Default: ALLOW
    prog.push(bpf_stmt(BPF_RET | BPF_K, 0x7fff_0000)); // SECCOMP_RET_ALLOW

    Ok(prog)
}

/// Collect the syscall numbers to intercept based on the audit config.
pub fn target_syscalls(audit_file_access: bool, audit_network: bool) -> Vec<i64> {
    let mut syscalls = Vec::new();

    if audit_file_access {
        syscalls.push(libc::SYS_openat);
        // openat2 (kernel 5.6+, syscall 437 on both x86_64 and aarch64)
        syscalls.push(437);
        #[cfg(target_arch = "x86_64")]
        syscalls.push(libc::SYS_open);
        syscalls.push(libc::SYS_execve);
        syscalls.push(libc::SYS_execveat);
    }

    if audit_network {
        syscalls.push(libc::SYS_connect);
        syscalls.push(libc::SYS_sendto);
        syscalls.push(libc::SYS_sendmsg);
        syscalls.push(libc::SYS_sendmmsg);
    }

    syscalls
}

// ─── Filter installation ──────────────────────────────────────────

/// Install a USER_NOTIF BPF filter and return the listener FD.
///
/// Uses `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER)`
/// directly (seccompiler doesn't support USER_NOTIF).
///
/// The caller must have `PR_SET_NO_NEW_PRIVS` set before calling this.
/// The returned FD has `FD_CLOEXEC` set immediately.
pub fn install_unotify_filter(bpf: &[libc::sock_filter]) -> crate::Result<RawFd> {
    let prog = libc::sock_fprog {
        len: bpf.len() as u16,
        filter: bpf.as_ptr() as *mut libc::sock_filter,
    };

    // SAFETY: seccomp syscall with valid prog pointer. The return value
    // is the listener FD on success, or -1 on error.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    } as i32;

    if fd < 0 {
        return Err(Error::Seccomp(format!(
            "seccomp USER_NOTIF filter installation failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Defense-in-depth: set CLOEXEC so the target process can't inherit
    // the listener FD if the explicit close is missed.
    // SAFETY: fd is a valid descriptor just returned by seccomp().
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };

    Ok(fd)
}

// ─── Ioctl wrappers ───────────────────────────────────────────────

/// Receive a seccomp notification from the listener FD.
///
/// Blocks until a notification is available.
/// Returns `ENOENT` when the filter is destroyed (target exited).
pub fn notif_recv(listener_fd: RawFd) -> std::io::Result<libc::seccomp_notif> {
    // SAFETY: zeroed seccomp_notif is valid for the ioctl.
    let mut notif: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(notif)
}

/// Send a response to a seccomp notification.
pub fn notif_send(listener_fd: RawFd, resp: &libc::seccomp_notif_resp) -> std::io::Result<()> {
    let ret = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Check if a notification ID is still valid (the target process hasn't
/// exited or been killed since the notification was received).
///
/// Tries the kernel 5.17+ ioctl encoding first, falls back to the
/// 5.0–5.16 encoding if the new one returns ENOTTY.
pub fn notif_id_valid(listener_fd: RawFd, id: u64) -> bool {
    let mut id_mut = id;
    let ret = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID_NEW, &mut id_mut) };
    if ret == 0 {
        return true;
    }
    let errno = std::io::Error::last_os_error().raw_os_error();
    if errno == Some(libc::ENOTTY) || errno == Some(libc::EINVAL) {
        id_mut = id;
        let ret =
            unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID_OLD, &mut id_mut) };
        return ret == 0;
    }
    false
}

// ─── /proc/<pid>/mem reader ────────────────────────────────────────

/// RAII wrapper for a `/proc/<pid>/mem` file descriptor.
///
/// Opened once per notification and passed to all read helpers,
/// avoiding repeated open/close cycles for the same PID.
struct MemFd(RawFd);

impl MemFd {
    fn open(pid: u32) -> Option<Self> {
        let mem_path = format!("/proc/{pid}/mem\0");
        let fd = unsafe { libc::open(mem_path.as_ptr().cast(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 { None } else { Some(Self(fd)) }
    }

    fn pread(&self, buf: &mut [u8], offset: u64) -> isize {
        unsafe {
            libc::pread(
                self.0,
                buf.as_mut_ptr().cast(),
                buf.len(),
                offset as libc::off_t,
            )
        }
    }

    fn fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for MemFd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// Read a NUL-terminated string from a target process's memory.
///
/// Reads up to `max_len` bytes at `addr` via the cached `MemFd`,
/// scanning for a NUL terminator. Returns `None` if the address is
/// NULL, unmapped, or the read fails for any reason.
fn read_string(mem: &MemFd, addr: u64, max_len: usize) -> Option<String> {
    if addr == 0 {
        return None;
    }

    let cap = max_len.min(4096);
    let mut buf = [0u8; 4096];
    let n = mem.pread(&mut buf[..cap], addr);

    if n <= 0 {
        return None;
    }
    let n = n as usize;

    // Find NUL terminator.
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    String::from_utf8_lossy(&buf[..end]).into_owned().into()
}

/// Parsed sockaddr information.
#[derive(Debug)]
pub struct SockaddrInfo {
    /// Address family (AF_INET, AF_INET6, etc.).
    pub family: u16,
    /// Human-readable destination (e.g., "1.2.3.4:443").
    pub destination: String,
    /// Port number.
    pub port: u16,
}

/// Parsed AF_UNIX sockaddr contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnixSockaddr {
    /// Filesystem socket: `sun_path[0] != 0` and NUL-terminated
    /// within the given length.
    Path(String),
    /// Abstract-namespace socket: `sun_path[0] == 0`; the name is
    /// the raw bytes after the leading NUL (length-delimited, not
    /// NUL-terminated).
    Abstract(Vec<u8>),
    /// No path bytes at all (`addrlen == sizeof(sa_family_t)`).
    Unnamed,
    /// Filesystem path not NUL-terminated within the given length —
    /// structurally invalid for `connect()`.
    Unterminated,
}

/// Result of reading a sockaddr from a target process.
#[derive(Debug)]
pub enum SockaddrResult {
    /// Successfully read an AF_INET or AF_INET6 address.
    Inet(SockaddrInfo),
    /// Successfully read an AF_UNIX address (filesystem path,
    /// abstract name, unnamed, or structurally unterminated).
    Unix(UnixSockaddr),
    /// Successfully read the family but it's neither INET nor UNIX
    /// (AF_NETLINK, etc.).
    NonInet(u16),
    /// Failed to read the sockaddr (process exited, unmapped, etc.).
    ReadFailed,
}

/// Read a sockaddr from a target process's memory via the cached `MemFd`.
fn read_sockaddr(mem: &MemFd, addr: u64, addrlen: u64) -> SockaddrResult {
    if addr == 0 || addrlen < 2 {
        return SockaddrResult::ReadFailed;
    }

    let mut family_buf = [0u8; 2];
    if mem.pread(&mut family_buf, addr) != 2 {
        return SockaddrResult::ReadFailed;
    }
    let family = u16::from_ne_bytes(family_buf);

    let fd = mem.fd();
    match family as i32 {
        libc::AF_INET if addrlen >= std::mem::size_of::<libc::sockaddr_in>() as u64 => {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let n = unsafe {
                libc::pread(
                    fd,
                    &mut sa as *mut libc::sockaddr_in as *mut libc::c_void,
                    std::mem::size_of::<libc::sockaddr_in>(),
                    addr as libc::off_t,
                )
            };
            if n == std::mem::size_of::<libc::sockaddr_in>() as isize {
                let port = u16::from_be(sa.sin_port);
                let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                SockaddrResult::Inet(SockaddrInfo {
                    family,
                    destination: format!("{ip}:{port}"),
                    port,
                })
            } else {
                SockaddrResult::ReadFailed
            }
        }
        libc::AF_INET6 if addrlen >= std::mem::size_of::<libc::sockaddr_in6>() as u64 => {
            let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            let n = unsafe {
                libc::pread(
                    fd,
                    &mut sa as *mut libc::sockaddr_in6 as *mut libc::c_void,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                    addr as libc::off_t,
                )
            };
            if n == std::mem::size_of::<libc::sockaddr_in6>() as isize {
                let port = u16::from_be(sa.sin6_port);
                let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
                SockaddrResult::Inet(SockaddrInfo {
                    family,
                    destination: format!("[{ip}]:{port}"),
                    port,
                })
            } else {
                SockaddrResult::ReadFailed
            }
        }
        libc::AF_INET | libc::AF_INET6 => SockaddrResult::ReadFailed, // addrlen too short
        libc::AF_UNIX => {
            // The kernel rejects connect() sockaddrs longer than
            // sizeof(sockaddr_un); cap the read so we never touch
            // memory beyond min(addrlen, sizeof(sockaddr_un)).
            const SOCKADDR_UN_SIZE: u64 = std::mem::size_of::<libc::sockaddr_un>() as u64;
            let len = addrlen.min(SOCKADDR_UN_SIZE);
            let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            let n = unsafe {
                libc::pread(
                    fd,
                    &mut sa as *mut libc::sockaddr_un as *mut libc::c_void,
                    len as usize,
                    addr as libc::off_t,
                )
            };
            if n != len as isize {
                return SockaddrResult::ReadFailed;
            }
            let path_len = (len - std::mem::size_of::<libc::sa_family_t>() as u64) as usize;
            // SAFETY: sun_path is a fixed-size array of c_char living
            // for the duration of this function; path_len is bounded
            // by the sockaddr_un size.
            let path_bytes: &[u8] =
                unsafe { std::slice::from_raw_parts(sa.sun_path.as_ptr().cast::<u8>(), path_len) };
            if path_bytes.is_empty() {
                SockaddrResult::Unix(UnixSockaddr::Unnamed)
            } else if path_bytes[0] == 0 {
                SockaddrResult::Unix(UnixSockaddr::Abstract(path_bytes[1..].to_vec()))
            } else {
                match path_bytes.iter().position(|&b| b == 0) {
                    Some(end) => SockaddrResult::Unix(UnixSockaddr::Path(
                        String::from_utf8_lossy(&path_bytes[..end]).into_owned(),
                    )),
                    None => SockaddrResult::Unix(UnixSockaddr::Unterminated),
                }
            }
        }
        _ => SockaddrResult::NonInet(family),
    }
}

// ─── Notification handler ─────────────────────────────────────────

const SYS_OPENAT2: i64 = 437;

/// Handle a single seccomp notification.
///
/// Opens `/proc/<pid>/mem` once and passes it to all read helpers,
/// dispatches by syscall number, writes an NDJSON audit line, and
/// responds with either CONTINUE (observation) or ECONNREFUSED
/// (network blocking).
///
/// Returns `true` if a response was sent, `false` if the notification
/// was stale (target exited between recv and send).
pub fn handle_notification(
    listener_fd: RawFd,
    notif: &libc::seccomp_notif,
    audit_fd: RawFd,
    config: &UnotifyConfig,
    dropped: &mut u64,
) -> bool {
    let pid = notif.pid;
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;

    let Some(mem) = MemFd::open(pid) else {
        return respond_continue(listener_fd, notif);
    };

    match nr {
        libc::SYS_openat | SYS_OPENAT2 => {
            // openat(dirfd, pathname, flags, mode)
            // openat2(dirfd, pathname, &open_how, size)
            let path_addr = args[1];
            let flags = if nr == SYS_OPENAT2 {
                // open_how.flags is the first field (u64)
                read_u64(&mem, args[2]).unwrap_or(0) as u32
            } else {
                args[2] as u32
            };
            let path = read_string(&mem, path_addr, 2000).unwrap_or_default();
            let is_write =
                flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC) as u32 != 0;
            write_audit_line(
                audit_fd,
                dropped,
                &format!(
                    "{{\"type\":\"file_access\",\"pid\":{pid},\"path\":\"{}\",\"flags\":{flags},\"is_write\":{is_write}}}",
                    escape_for_audit(&path),
                ),
            );
            respond_continue(listener_fd, notif)
        }
        #[cfg(target_arch = "x86_64")]
        libc::SYS_open => {
            // open(pathname, flags, mode) — x86_64 only
            let path_addr = args[0];
            let flags = args[1] as u32;
            let path = read_string(&mem, path_addr, 2000).unwrap_or_default();
            let is_write =
                flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC) as u32 != 0;
            write_audit_line(
                audit_fd,
                dropped,
                &format!(
                    "{{\"type\":\"file_access\",\"pid\":{pid},\"path\":\"{}\",\"flags\":{flags},\"is_write\":{is_write}}}",
                    escape_for_audit(&path),
                ),
            );
            respond_continue(listener_fd, notif)
        }
        libc::SYS_execve | libc::SYS_execveat => {
            // execve(pathname, argv, envp) — pathname is arg0
            // execveat(dirfd, pathname, argv, envp, flags) — pathname is arg1
            let path_addr = if nr == libc::SYS_execveat {
                args[1]
            } else {
                args[0]
            };
            let binary = read_string(&mem, path_addr, 2000).unwrap_or_default();
            write_audit_line(
                audit_fd,
                dropped,
                &format!(
                    "{{\"type\":\"process_spawn\",\"pid\":{pid},\"binary\":\"{}\"}}",
                    escape_for_audit(&binary),
                ),
            );
            respond_continue(listener_fd, notif)
        }
        libc::SYS_connect => {
            // connect(sockfd, addr, addrlen)
            handle_connect(
                listener_fd,
                notif,
                &mem,
                audit_fd,
                config,
                dropped,
                args[1],
                args[2],
                "connect",
            )
        }
        libc::SYS_sendto => {
            // sendto(sockfd, buf, len, flags, dest_addr, addrlen)
            if args[4] == 0 {
                // NULL dest_addr: connected socket send, allow through.
                respond_continue(listener_fd, notif)
            } else {
                handle_connect(
                    listener_fd,
                    notif,
                    &mem,
                    audit_fd,
                    config,
                    dropped,
                    args[4],
                    args[5],
                    "sendto",
                )
            }
        }
        libc::SYS_sendmsg => {
            // sendmsg(sockfd, &msghdr, flags)
            handle_sendmsg(
                listener_fd,
                notif,
                &mem,
                audit_fd,
                config,
                dropped,
                args[1],
                "sendmsg",
            )
        }
        libc::SYS_sendmmsg => {
            // sendmmsg(sockfd, &mmsghdr_vec, vlen, flags)
            // Validate ALL messages before responding — a single
            // respond_continue resumes the entire batch.
            // sizeof(struct mmsghdr) = 64 on LP64 (msghdr=56 + msg_len=4 + pad=4).
            const MAX_SENDMMSG_INSPECT: u64 = 64;
            if args[2] > MAX_SENDMMSG_INSPECT && config.enforce_network {
                return respond_errno(listener_fd, notif, libc::ECONNREFUSED);
            }
            let vlen = args[2].min(MAX_SENDMMSG_INSPECT);
            const MMSGHDR_SIZE: u64 = 64;
            let mut block = false;
            for i in 0..vlen {
                let msghdr_addr = args[1] + i * MMSGHDR_SIZE;
                if sendmsg_should_block(&mem, msghdr_addr, config) {
                    // Emit audit event for this blocked destination.
                    let msg_name = read_u64(&mem, msghdr_addr);
                    let msg_namelen = read_u32(&mem, msghdr_addr + 8);
                    if let (Some(addr), Some(len)) = (msg_name, msg_namelen) {
                        if addr != 0 && len > 0 {
                            if let SockaddrResult::Inet(info) =
                                read_sockaddr(&mem, addr, len as u64)
                            {
                                write_audit_line(
                                    audit_fd,
                                    dropped,
                                    &format!(
                                        "{{\"type\":\"network_blocked\",\"pid\":{pid},\"dest\":\"{}\",\"syscall\":\"sendmmsg\"}}",
                                        escape_for_audit(&info.destination),
                                    ),
                                );
                            }
                        }
                    }
                    block = true;
                }
            }
            if block && config.enforce_network {
                respond_errno(listener_fd, notif, libc::ECONNREFUSED)
            } else {
                respond_continue(listener_fd, notif)
            }
        }
        _ => {
            // Unexpected syscall — allow through.
            respond_continue(listener_fd, notif)
        }
    }
}

/// Handle a connect-like syscall (connect, sendto with non-NULL addr).
///
/// SECURITY: The TOCTOU race inherent to SECCOMP_USER_NOTIF_FLAG_CONTINUE
/// means a multi-threaded target can modify the sockaddr between the
/// supervisor's read and the kernel's re-execution. Network blocking via
/// unotify is defense-in-depth only — the network namespace (use_netns)
/// is the primary security boundary.
#[allow(clippy::too_many_arguments)]
fn handle_connect(
    listener_fd: RawFd,
    notif: &libc::seccomp_notif,
    mem: &MemFd,
    audit_fd: RawFd,
    config: &UnotifyConfig,
    dropped: &mut u64,
    addr: u64,
    addrlen: u64,
    syscall: &str,
) -> bool {
    let pid = notif.pid;

    match read_sockaddr(mem, addr, addrlen) {
        SockaddrResult::Inet(info) => {
            if is_bridge_addr(&info, config) {
                respond_continue(listener_fd, notif)
            } else {
                write_audit_line(
                    audit_fd,
                    dropped,
                    &format!(
                        "{{\"type\":\"network_blocked\",\"pid\":{pid},\"dest\":\"{}\",\"syscall\":\"{syscall}\"}}",
                        escape_for_audit(&info.destination),
                    ),
                );
                if config.enforce_network {
                    respond_errno(listener_fd, notif, libc::ECONNREFUSED)
                } else {
                    respond_continue(listener_fd, notif)
                }
            }
        }
        SockaddrResult::Unix(_) => {
            // AF_UNIX — audit-only mode does not enforce Unix socket
            // connects; allow through (the connect broker handles
            // these when the UDS policy is active).
            respond_continue(listener_fd, notif)
        }
        SockaddrResult::NonInet(_) => {
            // AF_NETLINK, etc. — not INET, allow through.
            respond_continue(listener_fd, notif)
        }
        SockaddrResult::ReadFailed => {
            // Failed to read sockaddr. Fail-closed for enforcement mode:
            // we can't verify the destination, so block it.
            if config.enforce_network {
                respond_errno(listener_fd, notif, libc::ECONNREFUSED)
            } else {
                respond_continue(listener_fd, notif)
            }
        }
    }
}

/// Check if a msghdr's destination address should be blocked.
///
/// Returns true if the destination is a non-bridge INET address
/// (i.e., would be blocked by network enforcement). Does NOT emit
/// a seccomp response — the caller must respond after checking all
/// messages in a batch.
fn sendmsg_should_block(mem: &MemFd, msghdr_addr: u64, config: &UnotifyConfig) -> bool {
    let msg_name = read_u64(mem, msghdr_addr);
    let msg_namelen = read_u32(mem, msghdr_addr + 8);

    match (msg_name, msg_namelen) {
        (Some(name_addr), Some(namelen)) if name_addr != 0 && namelen > 0 => {
            match read_sockaddr(mem, name_addr, namelen as u64) {
                SockaddrResult::Inet(info) => !is_bridge_addr(&info, config),
                SockaddrResult::Unix(_) => false,
                SockaddrResult::NonInet(_) => false,
                SockaddrResult::ReadFailed => config.enforce_network,
            }
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_sendmsg(
    listener_fd: RawFd,
    notif: &libc::seccomp_notif,
    mem: &MemFd,
    audit_fd: RawFd,
    config: &UnotifyConfig,
    dropped: &mut u64,
    msghdr_addr: u64,
    syscall: &str,
) -> bool {
    // Read msg_name (pointer) and msg_namelen from msghdr.
    // struct msghdr { void *msg_name; socklen_t msg_namelen; ... }
    // On 64-bit: msg_name at offset 0 (8 bytes), msg_namelen at offset 8 (4 bytes).
    let msg_name = read_u64(mem, msghdr_addr);
    let msg_namelen = read_u32(mem, msghdr_addr + 8);

    match (msg_name, msg_namelen) {
        (Some(name_addr), Some(namelen)) if name_addr != 0 && namelen > 0 => handle_connect(
            listener_fd,
            notif,
            mem,
            audit_fd,
            config,
            dropped,
            name_addr,
            namelen as u64,
            syscall,
        ),
        _ => {
            // NULL msg_name or failed read — connected socket, allow.
            respond_continue(listener_fd, notif)
        }
    }
}

/// Check if a sockaddr points to the bridge or DNS capture address.
fn is_bridge_addr(info: &SockaddrInfo, config: &UnotifyConfig) -> bool {
    if !info.destination.starts_with("127.0.0.1:") {
        return false;
    }
    if let Some(bridge_port) = config.bridge_port {
        if info.port == bridge_port {
            return true;
        }
    }
    if let Some(dns_port) = config.dns_port {
        if info.port == dns_port {
            return true;
        }
    }
    false
}

/// Read a u64 from a target process's memory via the cached `MemFd`.
fn read_u64(mem: &MemFd, addr: u64) -> Option<u64> {
    if addr == 0 {
        return None;
    }
    let mut buf = [0u8; 8];
    if mem.pread(&mut buf, addr) == 8 {
        Some(u64::from_ne_bytes(buf))
    } else {
        None
    }
}

/// Read a u32 from a target process's memory via the cached `MemFd`.
fn read_u32(mem: &MemFd, addr: u64) -> Option<u32> {
    if addr == 0 {
        return None;
    }
    let mut buf = [0u8; 4];
    if mem.pread(&mut buf, addr) == 4 {
        Some(u32::from_ne_bytes(buf))
    } else {
        None
    }
}

// ─── Response helpers ─────────────────────────────────────────────

/// Respond with CONTINUE (allow the syscall through).
fn respond_continue(listener_fd: RawFd, notif: &libc::seccomp_notif) -> bool {
    if !notif_id_valid(listener_fd, notif.id) {
        return false;
    }
    let resp = libc::seccomp_notif_resp {
        id: notif.id,
        val: 0,
        error: 0,
        flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
    };
    notif_send(listener_fd, &resp).is_ok()
}

/// Respond with an errno (block the syscall).
fn respond_errno(listener_fd: RawFd, notif: &libc::seccomp_notif, errno: i32) -> bool {
    if !notif_id_valid(listener_fd, notif.id) {
        return false;
    }
    let resp = libc::seccomp_notif_resp {
        id: notif.id,
        val: 0,
        error: -errno,
        flags: 0,
    };
    notif_send(listener_fd, &resp).is_ok()
}

/// Read exactly `buf.len()` bytes, retrying on EINTR and short reads.
fn read_exact_raw(fd: RawFd, buf: &mut [u8]) -> bool {
    let mut offset = 0;
    while offset < buf.len() {
        let n = unsafe { libc::read(fd, buf[offset..].as_mut_ptr().cast(), buf.len() - offset) };
        if n > 0 {
            offset += n as usize;
        } else if n == 0 {
            return false;
        } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else {
            return false;
        }
    }
    true
}

/// Write exactly `buf.len()` bytes, retrying on EINTR and short writes.
pub fn write_all_raw(fd: RawFd, buf: &[u8]) -> bool {
    let mut offset = 0;
    while offset < buf.len() {
        let n = unsafe { libc::write(fd, buf[offset..].as_ptr().cast(), buf.len() - offset) };
        if n > 0 {
            offset += n as usize;
        } else if n == 0 {
            return false;
        } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else {
            return false;
        }
    }
    true
}

/// JSON-escape a string and cap it to fit in an audit line.
///
/// `json_escape` can expand input significantly: `\` → `\\` (2x),
/// control chars → `\uXXXX` (6x). The escaped result is capped at
/// `MAX_ESCAPED` chars to guarantee the formatted NDJSON line fits
/// within PIPE_BUF.
const MAX_ESCAPED: usize = 3900;

fn escape_for_audit(s: &str) -> String {
    let escaped = crate::wrapper::json_escape(s);
    if escaped.len() <= MAX_ESCAPED {
        return escaped;
    }
    let mut end = MAX_ESCAPED;
    while end > 0 && !escaped.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = escaped[..end].to_string();
    truncated.push_str("...");
    truncated
}

/// Write an NDJSON audit line to the audit pipe.
///
/// The audit pipe is O_NONBLOCK. On EAGAIN, increments the drop counter
/// and skips the write. When the pipe becomes writable again and there
/// were drops, flushes a summary line.
fn write_audit_line(audit_fd: RawFd, dropped: &mut u64, line: &str) {
    // Flush drop summary if there were previous drops.
    if *dropped > 0 {
        let summary = format!("{{\"type\":\"dropped\",\"count\":{}}}\n", *dropped);
        let ret = unsafe { libc::write(audit_fd, summary.as_ptr().cast(), summary.len()) };
        if ret > 0 {
            *dropped = 0;
        }
    }

    // With escape_for_audit capping field values, the formatted line
    // should always fit within PIPE_BUF (4096). Log a warning if it
    // doesn't rather than writing broken JSON.
    if line.len() > 4095 {
        log::warn!(
            "audit line exceeds PIPE_BUF ({} bytes), dropping",
            line.len()
        );
        *dropped += 1;
        return;
    }

    let data = format!("{line}\n");
    let ret = unsafe { libc::write(audit_fd, data.as_ptr().cast(), data.len()) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            *dropped += 1;
        }
    }
}

// ─── Supervisor loop ──────────────────────────────────────────────

/// Main notification processing loop. Runs in the supervisor child.
///
/// Loops on `notif_recv()`, dispatches each notification to
/// `handle_notification()`, and exits when the listener FD becomes
/// invalid (target process exited, filter destroyed → ENOENT).
pub fn supervisor_loop(listener_fd: RawFd, audit_fd: RawFd, config: &UnotifyConfig) -> ! {
    let mut dropped: u64 = 0;

    loop {
        match notif_recv(listener_fd) {
            Ok(notif) => {
                handle_notification(listener_fd, &notif, audit_fd, config, &mut dropped);
            }
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(0);
                if errno == libc::EINTR {
                    continue;
                }
                // ENOENT: filter destroyed (target exited). Normal exit.
                // EBADF: listener FD closed. Also normal.
                if errno != libc::ENOENT && errno != libc::EBADF {
                    log::warn!("unotify supervisor: recv error: {e}");
                }
                break;
            }
        }
    }

    // Flush final drop count.
    if dropped > 0 {
        let summary = format!("{{\"type\":\"dropped\",\"count\":{dropped}}}\n");
        let _ = unsafe { libc::write(audit_fd, summary.as_ptr().cast(), summary.len()) };
    }

    unsafe { libc::_exit(0) }
}

// ─── Availability probe ───────────────────────────────────────────

static AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Check if the running kernel supports seccomp user notification with
/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (kernel ≥ 5.5).
///
/// Also probes cross-process `/proc/<pid>/mem` readability to detect
/// Yama `ptrace_scope` restrictions. Without a user namespace (which
/// grants `CAP_SYS_PTRACE`), `ptrace_scope=1` blocks the supervisor
/// from reading the target's memory.
///
/// Result is cached for the lifetime of the process.
pub fn unotify_available() -> bool {
    *AVAILABLE.get_or_init(probe_unotify_support)
}

fn probe_unotify_support() -> bool {
    // Phase 1: Check that we can read a sibling process's /proc/<pid>/mem.
    // This catches Yama ptrace_scope=1 without a user namespace.
    if !probe_proc_mem_access() {
        log::info!("unotify: /proc/<pid>/mem access blocked (Landlock, Yama, or LSM restriction)");
        return false;
    }

    // Phase 2: Check that seccomp USER_NOTIF + CONTINUE works.
    probe_seccomp_unotify()
}

fn probe_proc_mem_access() -> bool {
    // The supervisor (a child process) reads a sibling's /proc/<pid>/mem.
    // Under Yama ptrace_scope=1, parent→child always succeeds but
    // child→parent (or sibling→sibling) is blocked. We must test the
    // actual relationship: have a child try to read the parent's mem.
    let parent_pid = unsafe { libc::getpid() };
    // SAFETY: single-threaded at probe time (called during sandbox init).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        // Child: try to open the parent's /proc/<pid>/mem.
        let mem_path = format!("/proc/{parent_pid}/mem");
        let ok = std::fs::File::open(&mem_path).is_ok();
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }

    // Parent: wait for child and check exit code.
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
    ret > 0 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

fn probe_seccomp_unotify() -> bool {
    // We need to test in a clone child because installing a USER_NOTIF
    // filter on the current process would affect it permanently.
    // Build the BPF program before fork to avoid heap allocation in the
    // child (which is unsafe in multi-threaded processes).
    let bpf = match build_unotify_bpf(&[libc::SYS_getpid]) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // SAFETY: fork with pre-allocated BPF program. The child only uses
    // the inherited COW copy — no heap allocation needed.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        // Child: attempt to install a USER_NOTIF filter.
        // PR_SET_NO_NEW_PRIVS is required.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64) != 0 {
                libc::_exit(1);
            }
        }

        match install_unotify_filter(&bpf) {
            Ok(fd) => {
                unsafe { libc::close(fd) };
                // If we got here, USER_NOTIF is supported.
                // We can't easily test CONTINUE without a second thread,
                // but the fd creation confirms kernel >= 5.0 and the
                // SECCOMP_FILTER_FLAG_NEW_LISTENER flag. CONTINUE was
                // added in 5.5 — checking that the listener FD was
                // created is a strong signal (5.0 is very rare without 5.5).
                unsafe { libc::_exit(0) };
            }
            Err(_) => unsafe { libc::_exit(1) },
        }
    }

    // Parent: wait for child and check exit code.
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
    if ret <= 0 {
        return false;
    }
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

// ─── Configuration ────────────────────────────────────────────────

/// Configuration for the unotify supervisor.
pub struct UnotifyConfig {
    /// Intercept openat/openat2/open/execve/execveat.
    pub audit_file_access: bool,
    /// Intercept connect/sendto/sendmsg/sendmmsg.
    pub audit_network: bool,
    /// Bridge port to allow through (127.0.0.1:<port>).
    pub bridge_port: Option<u16>,
    /// DNS capture port to allow through (127.0.0.1:<port>).
    pub dns_port: Option<u16>,
    /// When true, block non-bridge INET connections with ECONNREFUSED.
    /// When false, log connections and allow them through (audit-only).
    /// Should only be true when `use_netns` is active (netns is the
    /// primary security boundary; unotify blocking is defense-in-depth).
    pub enforce_network: bool,
}

impl UnotifyConfig {
    pub fn any_enabled(&self) -> bool {
        self.audit_file_access || self.audit_network
    }
}

/// FDs returned by `fork_unotify_supervisor` for the caller to use.
pub struct UnotifyFds {
    /// Parent end of the socketpair for sending the listener FD.
    pub socketpair_parent: RawFd,
    /// Read end of the readiness pipe.
    pub readiness_read: RawFd,
}

// ─── Fork supervisor ──────────────────────────────────────────────

/// Fork the unotify supervisor child process.
///
/// The supervisor is forked BEFORE any seccomp filters are installed
/// to avoid inheriting the USER_NOTIF filter (which would deadlock
/// on the supervisor's own openat calls). The listener FD number is
/// sent to the supervisor via write() on a socketpair; the supervisor
/// duplicates it via pidfd_getfd().
///
/// Uses a **deferred readiness protocol**: the readiness pipe is
/// returned to the caller, not polled internally. The caller must:
/// 1. Poll `readiness_read` (confirms supervisor is alive)
/// 2. Install normal seccomp filters
/// 3. Install USER_NOTIF filter LAST → get listener FD
/// 4. Write listener FD number via `write(socketpair_parent, &fd)`
/// 5. Close socketpair_parent (keep listener_fd for pidfd_getfd)
///
/// The supervisor reads the FD number, duplicates it via pidfd_getfd.
///
/// `audit_write_fd` is the write end of the audit pipe (created by
/// the library, passed via ARAPUCA_UNOTIFY_AUDIT_FD).
pub fn fork_unotify_supervisor(
    config: &UnotifyConfig,
    audit_write_fd: RawFd,
    seccomp_debug: bool,
) -> crate::Result<UnotifyFds> {
    // Create Unix socketpair for PID + FD number passing.
    let mut sv = [0i32; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } != 0
    {
        return Err(Error::Process(format!(
            "unotify: socketpair: {}",
            std::io::Error::last_os_error()
        )));
    }
    let sp_parent = sv[0];
    let sp_child = sv[1];

    // Create readiness pipe.
    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        unsafe {
            libc::close(sp_parent);
            libc::close(sp_child);
        }
        return Err(Error::Process(format!(
            "unotify: pipe2: {}",
            std::io::Error::last_os_error()
        )));
    }
    let readiness_read = pipe_fds[0];
    let readiness_write = pipe_fds[1];

    let parent_pid = unsafe { libc::getpid() };

    // Serialize config for the child (consumed after fork via COW).
    let child_config = UnotifyConfig {
        audit_file_access: config.audit_file_access,
        audit_network: config.audit_network,
        bridge_port: config.bridge_port,
        dns_port: config.dns_port,
        enforce_network: config.enforce_network,
    };

    // SAFETY: single-threaded at this point (between bridge fork and
    // seccomp apply, no threads spawned).
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        unsafe {
            libc::close(sp_parent);
            libc::close(sp_child);
            libc::close(readiness_read);
            libc::close(readiness_write);
        }
        return Err(Error::Process(format!(
            "unotify: fork: {}",
            std::io::Error::last_os_error()
        )));
    }

    if child_pid == 0 {
        // ── Supervisor child ─────────────────────────────────
        // All error exits use _exit (child can never return).

        unsafe { libc::close(sp_parent) };
        unsafe { libc::close(readiness_read) };

        // Close all FDs >= 3 except those we need.
        unsafe {
            crate::bridge::close_fds_except(&[sp_child, readiness_write, audit_write_fd]);
        }

        // Ignore SIGPIPE (audit pipe writes may fail).
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
            unsafe { libc::_exit(1) };
        }
        if unsafe { libc::getppid() } != parent_pid {
            unsafe { libc::_exit(1) };
        }
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
            unsafe { libc::_exit(1) };
        }
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64) } != 0 {
            unsafe { libc::_exit(1) };
        }

        // Apply the supervisor's own seccomp allowlist.
        #[cfg(seccomp_supported)]
        if let Err(_e) = apply_supervisor_seccomp(seccomp_debug) {
            crate::wrapper::write_stderr("unotify supervisor: seccomp failed\n");
            unsafe { libc::_exit(1) };
        }

        // Set audit pipe to non-blocking to avoid stalling on full pipe.
        unsafe {
            let flags = libc::fcntl(audit_write_fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(audit_write_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }

        // Signal readiness: supervisor is alive, seccomp applied,
        // waiting for the listener FD.
        unsafe {
            libc::write(readiness_write, [1u8].as_ptr().cast(), 1);
            libc::close(readiness_write);
        }

        // Read the wrapper's host PID and listener FD number from
        // the socketpair. The PID may differ from parent_pid when
        // pidns is active (the wrapper forks after the supervisor).
        let mut msg = [0u8; 8];
        if !read_exact_raw(sp_child, &mut msg) {
            unsafe {
                libc::close(sp_child);
                libc::_exit(1);
            }
        }
        unsafe { libc::close(sp_child) };
        let wrapper_pid = i32::from_ne_bytes(msg[..4].try_into().unwrap());
        let remote_fd = i32::from_ne_bytes(msg[4..].try_into().unwrap());
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, wrapper_pid, 0i32) } as i32;
        if pidfd < 0 {
            crate::wrapper::write_stderr("unotify supervisor: pidfd_open failed\n");
            unsafe { libc::_exit(1) };
        }
        let listener_fd =
            unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, remote_fd, 0u32) } as i32;
        unsafe { libc::close(pidfd) };
        if listener_fd < 0 {
            crate::wrapper::write_stderr("unotify supervisor: pidfd_getfd failed\n");
            unsafe { libc::_exit(1) };
        }

        // Enter the supervisor loop (never returns).
        supervisor_loop(listener_fd, audit_write_fd, &child_config);
    }

    // ── Parent (wrapper) ─────────────────────────────────────
    // (continues in the caller — install filter, write PID+FD,
    // then proceed to exec)
    unsafe {
        libc::close(sp_child);
        libc::close(readiness_write);
    }

    Ok(UnotifyFds {
        socketpair_parent: sp_parent,
        readiness_read,
    })
}

/// Read the caller's host PID from `/proc/self/stat`.
///
/// Inside a PID namespace, `getpid()` returns the namespace-local
/// PID (typically 1). This function reads the host PID from procfs,
/// which always reflects the initial PID namespace where `/proc` is
/// mounted.
pub fn read_host_pid() -> i32 {
    std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or_else(|| unsafe { libc::getpid() })
}

/// Apply the supervisor's own seccomp filter.
///
/// Derived from the bridge's allowlist (bridge.rs:build_bridge_filters)
/// but tailored for the supervisor's workload: ioctl (for seccomp
/// notification recv/send/id_valid), openat+pread64 (for /proc/pid/mem),
/// pidfd_open+pidfd_getfd (for listener FD transfer), and standard
/// runtime syscalls.
#[cfg(seccomp_supported)]
fn apply_supervisor_seccomp(debug: bool) -> crate::Result<()> {
    if debug {
        crate::seccomp::install_seccomp_debug_handler();
    }
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    };
    use std::collections::HashMap;

    let arch = crate::seccomp::target_arch()?;
    let mut allow: HashMap<i64, Vec<SeccompRule>> = HashMap::new();

    // I/O: /proc/<pid>/mem reading, audit pipe writing, socketpair recv,
    // pidfd_open+pidfd_getfd for listener FD transfer.
    for nr in [
        libc::SYS_openat,
        libc::SYS_read,
        libc::SYS_pread64,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_writev,
        libc::SYS_lseek,
        libc::SYS_ppoll,
        libc::SYS_fcntl,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
    ] {
        allow.insert(nr, vec![]);
    }

    // ioctl: restrict to seccomp notification commands only.
    let allowed_ioctls: [u64; 4] = [
        SECCOMP_IOCTL_NOTIF_RECV as _,
        SECCOMP_IOCTL_NOTIF_SEND as _,
        SECCOMP_IOCTL_NOTIF_ID_VALID_NEW as _,
        SECCOMP_IOCTL_NOTIF_ID_VALID_OLD as _,
    ];
    let mut ioctl_rules = Vec::new();
    for cmd in allowed_ioctls {
        ioctl_rules.push(
            SeccompRule::new(vec![
                SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, cmd)
                    .map_err(|e| Error::Seccomp(format!("ioctl condition: {e}")))?,
            ])
            .map_err(|e| Error::Seccomp(format!("ioctl rule: {e}")))?,
        );
    }
    allow.insert(libc::SYS_ioctl, ioctl_rules);
    #[cfg(target_arch = "x86_64")]
    {
        allow.insert(libc::SYS_poll, vec![]);
    }

    // Memory management.
    for nr in [
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_mremap,
        libc::SYS_madvise,
    ] {
        allow.insert(nr, vec![]);
    }

    // mprotect: deny PROT_EXEC.
    let mprotect_rule = SeccompRule::new(vec![
        SeccompCondition::new(
            2,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
            0,
        )
        .map_err(|e| Error::Seccomp(format!("supervisor mprotect condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("supervisor mprotect rule: {e}")))?;
    allow.insert(libc::SYS_mprotect, vec![mprotect_rule]);

    // Signals.
    for nr in [
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
    ] {
        allow.insert(nr, vec![]);
    }

    // Process lifecycle.
    for nr in [libc::SYS_exit, libc::SYS_exit_group] {
        allow.insert(nr, vec![]);
    }

    // Thread management + runtime.
    for nr in [
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_gettid,
        libc::SYS_getpid,
        libc::SYS_tgkill,
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_prlimit64,
        libc::SYS_rseq,
        libc::SYS_newfstatat,
        libc::SYS_fstat,
        libc::SYS_nanosleep,
    ] {
        allow.insert(nr, vec![]);
    }

    // clone3 in allowlist so the stacked ENOSYS filter wins over
    // KillProcess (ENOSYS is more restrictive than Allow, less
    // restrictive than KillProcess).
    allow.insert(libc::SYS_clone3, vec![]);

    // prctl: allow VMA naming (glibc malloc arena labeling under
    // concurrent thread load) and thread naming.
    const PR_SET_VMA: u64 = 0x53564d41;
    let prctl_set_vma = SeccompRule::new(vec![
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, PR_SET_VMA)
            .map_err(|e| Error::Seccomp(format!("prctl PR_SET_VMA condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("prctl PR_SET_VMA rule: {e}")))?;
    let prctl_set_name = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::PR_SET_NAME as u64,
        )
        .map_err(|e| Error::Seccomp(format!("prctl PR_SET_NAME condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("prctl PR_SET_NAME rule: {e}")))?;
    allow.insert(libc::SYS_prctl, vec![prctl_set_vma, prctl_set_name]);

    let mismatch = if debug {
        SeccompAction::Trap
    } else {
        SeccompAction::KillProcess
    };
    let filter = SeccompFilter::new(
        allow.into_iter().collect(),
        mismatch,
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build supervisor filter: {e}")))?;

    let prog: seccompiler::BpfProgram =
        filter.try_into().map_err(|e: seccompiler::BackendError| {
            Error::Seccomp(format!("compile supervisor filter: {e}"))
        })?;

    // clone3 → ENOSYS so glibc falls back to clone (which is not in
    // the allowlist either — the supervisor is single-threaded). This
    // must be a separate stacked filter because seccompiler only
    // supports one match action per filter.
    let mut clone3_deny: HashMap<i64, Vec<SeccompRule>> = HashMap::new();
    clone3_deny.insert(libc::SYS_clone3, vec![]);
    let clone3_filter = SeccompFilter::new(
        clone3_deny.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build supervisor clone3 filter: {e}")))?;
    let clone3_prog: seccompiler::BpfProgram =
        clone3_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                Error::Seccomp(format!("compile supervisor clone3 filter: {e}"))
            })?;

    // Install clone3 ENOSYS first, then allowlist (last installed is
    // checked first; most restrictive action wins).
    seccompiler::apply_filter(&clone3_prog)
        .map_err(|e| Error::Seccomp(format!("install supervisor clone3 filter: {e}")))?;
    seccompiler::apply_filter(&prog)
        .map_err(|e| Error::Seccomp(format!("install supervisor filter: {e}")))?;

    log::info!("unotify supervisor: seccomp filter applied");
    Ok(())
}

/// Poll the readiness pipe with a timeout.
///
/// Used by the caller after `fork_unotify_supervisor` returns to
/// confirm the supervisor child is alive before proceeding.
pub fn poll_readiness(readiness_fd: RawFd, timeout_ms: i32) -> crate::Result<()> {
    let mut pfd = libc::pollfd {
        fd: readiness_fd,
        events: libc::POLLIN,
        revents: 0,
    };

    let poll_ret = loop {
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break ret;
        }
    };

    if poll_ret == 0 {
        return Err(Error::Process(
            "unotify supervisor readiness timeout".into(),
        ));
    }
    if poll_ret < 0 {
        return Err(Error::Process(format!(
            "unotify supervisor poll: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut buf = [0u8; 1];
    let n = loop {
        let ret = unsafe { libc::read(readiness_fd, buf.as_mut_ptr().cast(), 1) };
        if ret >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break ret;
        }
    };

    if n != 1 {
        return Err(Error::Process(
            "unotify supervisor readiness signal failed".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_program_has_correct_structure() {
        let syscalls = vec![libc::SYS_openat, libc::SYS_execve];
        let bpf = build_unotify_bpf(&syscalls).unwrap();
        // 3 header (load arch, arch check, load nr) +
        // 2 syscalls × 2 (compare + return) + 1 default allow = 8
        assert_eq!(bpf.len(), 8);
    }

    #[test]
    fn bpf_program_empty_syscalls() {
        let bpf = build_unotify_bpf(&[]).unwrap();
        // load arch + arch check + load nr + default allow = 4
        assert_eq!(bpf.len(), 4);
    }

    #[test]
    fn bpf_first_instruction_loads_arch() {
        let bpf = build_unotify_bpf(&[libc::SYS_openat]).unwrap();
        assert_eq!(bpf[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(bpf[0].k, 4); // offset of arch in seccomp_data
    }

    #[test]
    fn bpf_last_instruction_is_allow() {
        let bpf = build_unotify_bpf(&[libc::SYS_openat]).unwrap();
        let last = bpf.last().unwrap();
        assert_eq!(last.code, BPF_RET | BPF_K);
        assert_eq!(last.k, 0x7fff_0000); // SECCOMP_RET_ALLOW
    }

    #[test]
    fn bpf_contains_user_notif_return() {
        let bpf = build_unotify_bpf(&[libc::SYS_openat]).unwrap();
        let has_notif = bpf
            .iter()
            .any(|i| i.code == BPF_RET | BPF_K && i.k == libc::SECCOMP_RET_USER_NOTIF);
        assert!(
            has_notif,
            "BPF should contain SECCOMP_RET_USER_NOTIF return"
        );
    }

    #[test]
    fn target_syscalls_file_access() {
        let syscalls = target_syscalls(true, false);
        assert!(syscalls.contains(&libc::SYS_openat));
        assert!(syscalls.contains(&437)); // openat2
        assert!(syscalls.contains(&libc::SYS_execve));
        assert!(syscalls.contains(&libc::SYS_execveat));
        assert!(!syscalls.contains(&libc::SYS_connect));
    }

    #[test]
    fn target_syscalls_network() {
        let syscalls = target_syscalls(false, true);
        assert!(syscalls.contains(&libc::SYS_connect));
        assert!(syscalls.contains(&libc::SYS_sendto));
        assert!(syscalls.contains(&libc::SYS_sendmsg));
        assert!(syscalls.contains(&libc::SYS_sendmmsg));
        assert!(!syscalls.contains(&libc::SYS_openat));
    }

    #[test]
    fn target_syscalls_both() {
        let syscalls = target_syscalls(true, true);
        assert!(syscalls.contains(&libc::SYS_openat));
        assert!(syscalls.contains(&libc::SYS_connect));
    }

    #[test]
    fn target_syscalls_neither() {
        let syscalls = target_syscalls(false, false);
        assert!(syscalls.is_empty());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn target_syscalls_includes_open_on_x86_64() {
        let syscalls = target_syscalls(true, false);
        assert!(syscalls.contains(&libc::SYS_open));
    }

    #[test]
    fn ioctl_constants_are_nonzero() {
        assert_ne!(SECCOMP_IOCTL_NOTIF_RECV, 0);
        assert_ne!(SECCOMP_IOCTL_NOTIF_SEND, 0);
        assert_ne!(SECCOMP_IOCTL_NOTIF_ID_VALID_NEW, 0);
        assert_ne!(SECCOMP_IOCTL_NOTIF_ID_VALID_OLD, 0);
    }

    #[test]
    fn ioctl_constants_are_distinct() {
        assert_ne!(SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_SEND);
        assert_ne!(SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_ID_VALID_NEW);
        assert_ne!(SECCOMP_IOCTL_NOTIF_SEND, SECCOMP_IOCTL_NOTIF_ID_VALID_NEW);
    }

    #[test]
    fn ioctl_id_valid_old_differs_from_new() {
        assert_ne!(
            SECCOMP_IOCTL_NOTIF_ID_VALID_OLD,
            SECCOMP_IOCTL_NOTIF_ID_VALID_NEW
        );
    }

    #[test]
    fn bpf_rejects_too_many_syscalls() {
        let many: Vec<i64> = (0..128).collect();
        assert!(build_unotify_bpf(&many).is_err());
    }

    #[test]
    fn bpf_accepts_max_syscalls() {
        let max: Vec<i64> = (0..127).collect();
        assert!(build_unotify_bpf(&max).is_ok());
    }

    #[test]
    fn unotify_config_any_enabled() {
        assert!(
            !UnotifyConfig {
                audit_file_access: false,
                audit_network: false,
                bridge_port: None,
                dns_port: None,
                enforce_network: false,
            }
            .any_enabled()
        );
        assert!(
            UnotifyConfig {
                audit_file_access: true,
                audit_network: false,
                bridge_port: None,
                dns_port: None,
                enforce_network: false,
            }
            .any_enabled()
        );
        assert!(
            UnotifyConfig {
                audit_file_access: false,
                audit_network: true,
                bridge_port: Some(8080),
                dns_port: None,
                enforce_network: true,
            }
            .any_enabled()
        );
    }

    #[test]
    fn probe_function_returns_result() {
        // Just verify the probe doesn't panic or hang.
        // The actual result depends on kernel version.
        let _ = unotify_available();
    }

    #[test]
    fn supervisor_seccomp_allows_required_syscalls() {
        // Smoke test: fork a child, apply the supervisor seccomp,
        // verify write(2) succeeds (if the filter is inverted,
        // write is in the allowlist and would be killed).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64);
            }
            #[cfg(seccomp_supported)]
            if apply_supervisor_seccomp(false).is_err() {
                unsafe { libc::_exit(2) };
            }
            // If the filter is correct, write succeeds.
            // If inverted, SECCOMP_RET_KILL_PROCESS kills us here.
            let ret = unsafe { libc::write(2, b"ok\n".as_ptr().cast(), 3) };
            if ret < 0 {
                unsafe { libc::_exit(3) };
            }
            unsafe { libc::_exit(0) };
        }
        let mut status: libc::c_int = 0;
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(ret > 0, "waitpid failed");
        assert!(
            libc::WIFEXITED(status),
            "child should exit normally, not be killed by seccomp"
        );
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    // ─── AF_UNIX sockaddr parsing ─────────────────────────────────

    /// Read a sockaddr from this process's own memory via /proc/self/mem.
    fn read_own_sockaddr(bytes: &[u8], addrlen: u64) -> SockaddrResult {
        let mem = MemFd::open(std::process::id()).expect("open own /proc/pid/mem");
        read_sockaddr(&mem, bytes.as_ptr() as u64, addrlen)
    }

    /// Build a sockaddr_un with the given path and compute addrlen
    /// the way a caller passing a NUL-terminated path would.
    fn unix_sa(path: &[u8]) -> (libc::sockaddr_un, u64) {
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, &b) in path.iter().enumerate() {
            sa.sun_path[i] = b as libc::c_char;
        }
        let addrlen = std::mem::size_of::<libc::sa_family_t>() + path.len() + 1;
        (sa, addrlen as u64)
    }

    /// Build an abstract-namespace sockaddr_un: leading NUL plus the
    /// name, length-delimited with no trailing NUL.
    fn unix_abstract_sa(name: &[u8]) -> (libc::sockaddr_un, u64) {
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
        sa.sun_path[0] = 0;
        for (i, &b) in name.iter().enumerate() {
            sa.sun_path[1 + i] = b as libc::c_char;
        }
        let addrlen = std::mem::size_of::<libc::sa_family_t>() + 1 + name.len();
        (sa, addrlen as u64)
    }

    fn sa_bytes(sa: &libc::sockaddr_un, len: u64) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(sa as *const _ as *const u8, len as usize) }.to_vec()
    }

    #[test]
    fn unix_sockaddr_filesystem_path() {
        let (sa, len) = unix_sa(b"/run/docker.sock");
        let bytes = sa_bytes(&sa, len);
        match read_own_sockaddr(&bytes, len) {
            SockaddrResult::Unix(UnixSockaddr::Path(p)) => assert_eq!(p, "/run/docker.sock"),
            other => panic!("expected Path, got {other:?}"),
        }
    }

    #[test]
    fn unix_sockaddr_abstract_name() {
        let (sa, len) = unix_abstract_sa(b"abstract-name");
        let bytes = sa_bytes(&sa, len);
        match read_own_sockaddr(&bytes, len) {
            SockaddrResult::Unix(UnixSockaddr::Abstract(n)) => {
                assert_eq!(n, b"abstract-name".to_vec())
            }
            other => panic!("expected Abstract, got {other:?}"),
        }
    }

    #[test]
    fn unix_sockaddr_abstract_empty_name() {
        let (sa, len) = unix_abstract_sa(b"");
        let bytes = sa_bytes(&sa, len);
        match read_own_sockaddr(&bytes, len) {
            SockaddrResult::Unix(UnixSockaddr::Abstract(n)) => assert!(n.is_empty()),
            other => panic!("expected Abstract(empty), got {other:?}"),
        }
    }

    #[test]
    fn unix_sockaddr_unnamed() {
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let len = std::mem::size_of::<libc::sa_family_t>() as u64;
        let bytes = sa_bytes(&sa, len);
        match read_own_sockaddr(&bytes, len) {
            SockaddrResult::Unix(UnixSockaddr::Unnamed) => {}
            other => panic!("expected Unnamed, got {other:?}"),
        }
    }

    #[test]
    fn unix_sockaddr_unterminated_path() {
        // Fill sun_path completely with non-NUL bytes.
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for b in sa.sun_path.iter_mut() {
            *b = b'a' as libc::c_char;
        }
        let len = std::mem::size_of::<libc::sockaddr_un>() as u64;
        let bytes = sa_bytes(&sa, len);
        match read_own_sockaddr(&bytes, len) {
            SockaddrResult::Unix(UnixSockaddr::Unterminated) => {}
            other => panic!("expected Unterminated, got {other:?}"),
        }
    }

    #[test]
    fn unix_sockaddr_read_caps_at_sockaddr_un_size() {
        // addrlen larger than sizeof(sockaddr_un): the read is capped
        // and a NUL within the zeroed tail still terminates the path.
        let (sa, _) = unix_sa(b"/tmp/short.sock");
        let len = std::mem::size_of::<libc::sockaddr_un>() as u64;
        let bytes = sa_bytes(&sa, len);
        match read_own_sockaddr(&bytes, len) {
            SockaddrResult::Unix(UnixSockaddr::Path(p)) => assert_eq!(p, "/tmp/short.sock"),
            other => panic!("expected Path, got {other:?}"),
        }
    }

    #[test]
    fn unix_sockaddr_short_read_fails() {
        // Place the sockaddr at the end of a mapped page followed by
        // an unmapped hole so the capped pread faults (PROT_NONE is
        // NOT enough: /proc/pid/mem reads use FOLL_FORCE and pass
        // through it).
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                (libc::sysconf(libc::_SC_PAGESIZE) * 2) as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        // Unmap the second page, leaving a hole after the first.
        let unmap =
            unsafe { libc::munmap((page as usize + page_size) as *mut libc::c_void, page_size) };
        assert_eq!(unmap, 0);

        // Sockaddr starts 4 bytes before the end of the mapped page;
        // a 110-byte read crosses into the hole.
        let sa_ptr = (page as usize + page_size - 4) as *mut libc::sockaddr_un;
        unsafe {
            std::ptr::write_unaligned(sa_ptr as *mut u16, libc::AF_UNIX as u16);
        }
        let mem = MemFd::open(std::process::id()).expect("open own /proc/pid/mem");
        let result = read_sockaddr(&mem, sa_ptr as u64, 110);
        unsafe { libc::munmap(page, page_size) };
        assert!(
            matches!(result, SockaddrResult::ReadFailed),
            "expected ReadFailed, got {result:?}"
        );
    }
}
