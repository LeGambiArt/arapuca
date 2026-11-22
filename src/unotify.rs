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

/// `ioctl(fd, SECCOMP_IOCTL_NOTIF_ADDFD, &seccomp_notif_addfd)` —
/// install a supervisor-owned fd into the target's fd table.
///
/// `struct seccomp_notif_addfd` is 24 bytes (u64 id + u32 flags +
/// u32 srcfd + u32 newfd + u32 newfd_flags), command nr 3. Not in
/// libc; computed from the kernel's `_IOW` macro. Kernel ≥ 5.9.
const SECCOMP_IOCTL_NOTIF_ADDFD: libc::Ioctl = ioc(IOC_WRITE, 3, 24);

/// With `SECCOMP_ADDFD_FLAG_SETFD`, the fd is installed at the
/// chosen `newfd` number (replacing whatever occupies it) instead of
/// the lowest free slot.
const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1 << 0;

/// Argument struct for `SECCOMP_IOCTL_NOTIF_ADDFD`.
#[repr(C)]
struct SeccompNotifAddfd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

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
///
/// See [`build_unotify_bpf_kill_arch`] for the variant used while the
/// UDS connect policy is active.
pub fn build_unotify_bpf(syscalls: &[i64]) -> crate::Result<Vec<libc::sock_filter>> {
    build_unotify_bpf_impl(syscalls, false)
}

/// Like [`build_unotify_bpf`], but syscalls entering through a
/// mismatched architecture (e.g. a 64-bit target issuing `int 0x80`
/// compat entry, which arrives with AUDIT_ARCH_I386 and bypasses the
/// broker) are killed instead of allowed.
///
/// Used while the UDS connect policy is active: an arch-mismatched
/// connect() would skip the broker entirely, so the filter must
/// fail closed. This breaks 32-bit-compat targets under the policy —
/// accepted.
pub fn build_unotify_bpf_kill_arch(syscalls: &[i64]) -> crate::Result<Vec<libc::sock_filter>> {
    build_unotify_bpf_impl(syscalls, true)
}

fn build_unotify_bpf_impl(
    syscalls: &[i64],
    kill_arch: bool,
) -> crate::Result<Vec<libc::sock_filter>> {
    if syscalls.len() > 127 {
        return Err(Error::Seccomp(format!(
            "unotify BPF: too many syscalls ({}, max 127)",
            syscalls.len()
        )));
    }
    // Arch-mismatch target: with kill_arch, mismatched entries (e.g.
    // int 0x80 compat) must die; the KILL return sits one instruction
    // past the default ALLOW so it is only reachable via this jump.
    let extra: u8 = if kill_arch { 1 } else { 0 };
    let mut prog = Vec::with_capacity(4 + syscalls.len() * 2 + 1 + extra as usize);

    // Load seccomp_data.arch (offset 4)
    prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 4));
    // Check arch matches — skip 1 instruction if match, else jump to
    // the mismatch action (ALLOW, or KILL for the kill_arch variant).
    let allow_offset = (syscalls.len() * 2) as u8;
    prog.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH,
        0,
        allow_offset + 1 + extra,
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
    if kill_arch {
        // Arch mismatch: kill (only reachable via the arch-check jump).
        prog.push(bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_KILL_PROCESS));
    }

    Ok(prog)
}

/// Collect the syscall numbers to intercept based on the audit config
/// and the UDS connect policy.
pub fn target_syscalls(
    audit_file_access: bool,
    audit_network: bool,
    enforce_unix_connect: bool,
) -> Vec<i64> {
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
    } else if enforce_unix_connect {
        // The connect broker intercepts connect() even without the
        // audit-network feature.
        syscalls.push(libc::SYS_connect);
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

/// Parse the `sun_path` bytes of an AF_UNIX sockaddr (everything
/// after the 2-byte family field, length-delimited by the sockaddr
/// length).
fn parse_unix_path_bytes(path_bytes: &[u8]) -> UnixSockaddr {
    if path_bytes.is_empty() {
        UnixSockaddr::Unnamed
    } else if path_bytes[0] == 0 {
        UnixSockaddr::Abstract(path_bytes[1..].to_vec())
    } else {
        match path_bytes.iter().position(|&b| b == 0) {
            Some(end) => {
                UnixSockaddr::Path(String::from_utf8_lossy(&path_bytes[..end]).into_owned())
            }
            None => UnixSockaddr::Unterminated,
        }
    }
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
            SockaddrResult::Unix(parse_unix_path_bytes(path_bytes))
        }
        _ => SockaddrResult::NonInet(family),
    }
}

// ─── UDS connect policy: deny-root matching ───────────────────────

/// Normalize the standard `/var/run` → `/run` symlink alias.
///
/// `getpeername()` returns the listener's bind()-time literal path,
/// not the resolved path, so a daemon that bound
/// `/var/run/docker.sock` reports that spelling even though the file
/// lives at `/run/docker.sock` on systemd hosts. Normalizing both
/// the peer literal and the roots covers the alias class in both
/// directions.
fn normalize_run_alias(path: &str) -> String {
    match path.strip_prefix("/var/run/") {
        Some(rest) => format!("/run/{rest}"),
        None => path.to_string(),
    }
}

/// Check whether a peer's literal bound path matches a deny root
/// (equal, or component-wise beneath it).
fn peer_matches_root(peer: &str, root: &str) -> bool {
    let peer = normalize_run_alias(peer);
    let root = normalize_run_alias(root);
    let root = root.trim_end_matches('/');
    peer == root || peer.starts_with(&format!("{root}/"))
}

/// Check whether a peer's literal bound path is denied by any root.
fn peer_denied(peer: &str, roots: &[String]) -> bool {
    roots.iter().any(|root| peer_matches_root(peer, root))
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
/// Under the UDS connect policy, `connect()` is routed to
/// [`broker_connect`] instead: emulation-or-deny, never CONTINUE.
///
/// Returns `true` if a response was sent, `false` if the notification
/// was stale (target exited between recv and send).
pub fn handle_notification(
    listener_fd: RawFd,
    notif: &libc::seccomp_notif,
    audit_fd: RawFd,
    config: &UnotifyConfig,
    dropped: &std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> bool {
    let pid = notif.pid;
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;

    // Opened once per notification. connect() under the UDS policy
    // requires it (fail-closed); audit-only syscalls keep the lenient
    // failure mode below.
    let mem = MemFd::open(pid);

    match nr {
        libc::SYS_connect if config.enforce_unix_connect => broker_connect(
            listener_fd,
            notif,
            mem.as_ref(),
            audit_fd,
            config,
            dropped,
            args[0],
            args[1],
            args[2],
        ),
        _ => match mem {
            // Audit-only syscalls tolerate inspection failure — but
            // silently continuing hides that the event was never
            // seen. An uninspectable process (re-parented descendant
            // on a plain Yama-1 run, or a non-dumpable exec) leaves
            // no record and no drop count, which reads as "nothing
            // happened". Write the failure itself as the audit line.
            None => {
                write_audit_line(
                    audit_fd,
                    dropped,
                    &format!("{{\"type\":\"inspection_failed\",\"pid\":{pid},\"nr\":{nr}}}\n"),
                );
                respond_continue(listener_fd, notif)
            }
            Some(mem) => handle_audit_syscall(listener_fd, notif, &mem, audit_fd, config, dropped),
        },
    }
}

/// Dispatch a non-brokered (audit-only) syscall notification.
///
/// The `connect`/`sendto`/`sendmsg`/`sendmmsg` arms here implement
/// the audit-network feature with its documented TOCTOU (netns is
/// the primary INET boundary); they are not reachable for
/// `connect()` while the UDS connect policy is active — that path is
/// handled by [`broker_connect`].
fn handle_audit_syscall(
    listener_fd: RawFd,
    notif: &libc::seccomp_notif,
    mem: &MemFd,
    audit_fd: RawFd,
    config: &UnotifyConfig,
    dropped: &std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> bool {
    let pid = notif.pid;
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;

    match nr {
        libc::SYS_openat | SYS_OPENAT2 => {
            // openat2(dirfd, pathname, &open_how, size)
            let path_addr = args[1];
            let flags = if nr == SYS_OPENAT2 {
                // open_how.flags is the first field (u64)
                read_u64(mem, args[2]).unwrap_or(0) as u32
            } else {
                args[2] as u32
            };
            let path = read_string(mem, path_addr, 2000).unwrap_or_default();
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
            let path = read_string(mem, path_addr, 2000).unwrap_or_default();
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
            let binary = read_string(mem, path_addr, 2000).unwrap_or_default();
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
                mem,
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
                    mem,
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
                mem,
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
                if sendmsg_should_block(mem, msghdr_addr, config) {
                    // Emit audit event for this blocked destination.
                    let msg_name = read_u64(mem, msghdr_addr);
                    let msg_namelen = read_u32(mem, msghdr_addr + 8);
                    if let (Some(addr), Some(len)) = (msg_name, msg_namelen) {
                        if addr != 0 && len > 0 {
                            if let SockaddrResult::Inet(info) = read_sockaddr(mem, addr, len as u64)
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
    dropped: &std::sync::Arc<std::sync::atomic::AtomicU64>,
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
    dropped: &std::sync::Arc<std::sync::atomic::AtomicU64>,
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

/// Respond with a successful return value (the kernel returns `val`
/// without re-executing the syscall).
fn respond_val(listener_fd: RawFd, notif: &libc::seccomp_notif, val: i64) -> bool {
    if !notif_id_valid(listener_fd, notif.id) {
        return false;
    }
    let resp = libc::seccomp_notif_resp {
        id: notif.id,
        val,
        error: 0,
        flags: 0,
    };
    notif_send(listener_fd, &resp).is_ok()
}

// ─── connect() broker (UDS connect policy) ────────────────────────
//
// While `enforce_unix_connect` is active, connect() notifications
// are fully emulated. The kernel never re-executes the syscall (no
// CONTINUE — the sockaddr buffer and fd table stay live across a
// CONTINUE, so it is a retryable TOCTOU), the address family is
// taken from the target's pinned file description (not from the
// buffer), and the supervisor dials a private socket created with
// the pinned socket's domain and type. On allow, the verified
// private socket is installed over the target's fd number via
// SECCOMP_IOCTL_NOTIF_ADDFD (SETFD); the target's original socket is
// never connected in any branch (deny, allow, or error), so a
// sibling thread spinning write() on it only ever sees ENOTCONN.

/// Maximum concurrent connect-completion helper threads. Beyond the
/// cap, connect notifications are answered EAGAIN (kernel-style
/// backpressure) rather than stalling the supervisor loop.
const MAX_CONNECT_HELPERS: usize = 64;

fn active_connect_helpers() -> &'static std::sync::atomic::AtomicUsize {
    static ACTIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    &ACTIVE
}

/// Snapshot a sockaddr (raw bytes) from the target's memory, capped
/// at `sizeof(sockaddr_storage)` — the kernel rejects anything
/// longer, and the cap keeps the read inside the caller's buffer.
fn read_sockaddr_snapshot(mem: &MemFd, addr: u64, addrlen: u64) -> Option<Vec<u8>> {
    const SOCKADDR_STORAGE_SIZE: u64 = 128;
    if addr == 0 {
        return None;
    }
    let len = addrlen.min(SOCKADDR_STORAGE_SIZE);
    let mut buf = vec![0u8; len as usize];
    if mem.pread(&mut buf, addr) != len as isize {
        return None;
    }
    Some(buf)
}

/// Resolve a task id to its thread-group leader's pid.
///
/// seccomp notifications report the id of the connecting THREAD,
/// but `pidfd_open` only accepts thread-group leaders (it returns
/// ENOENT for worker-thread ids). The fd table and address space
/// are shared across the thread group (CLONE_FILES/CLONE_VM), so
/// operating on the leader is equivalent for fd duplication and
/// memory reads. Multi-threaded runtimes (node, bun, JVM, Go)
/// issue connects from worker threads, making this resolution
/// load-bearing, not an edge case.
fn resolve_tgid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Duplicate a file descriptor from the target's fd table. The
/// kernel resolves the fd number at this moment, pinning the file
/// description the broker's decision applies to.
/// The target's FD_CLOEXEC state for `fd`, read from
/// `/proc/<pid>/fdinfo/<fd>` (the `flags:` octal field,
/// `02000000` = O_CLOEXEC). Returns None when fdinfo cannot be read.
fn target_fd_cloexec(pid: u32, fd: u64) -> Option<bool> {
    let path = format!("/proc/{pid}/fdinfo/{fd}");
    let info = std::fs::read_to_string(path).ok()?;
    for line in info.lines() {
        if let Some(rest) = line.strip_prefix("flags:") {
            let flags = u32::from_str_radix(rest.trim(), 8).ok()?;
            // fdinfo reports the O_* open-status mask, where the
            // close-on-exec bit is O_CLOEXEC (0o2000000) — not
            // fcntl's FD_CLOEXEC (1).
            return Some(flags & libc::O_CLOEXEC as u32 != 0);
        }
    }
    None
}

fn dup_target_fd(pid: u32, fd: u64) -> Option<RawFd> {
    // SAFETY: pidfd_open/pidfd_getfd on a live notification pid; the
    // returned fds are closed on every path.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0i32) } as i32;
    if pidfd < 0 {
        return None;
    }
    let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd as i32, 0u32) } as i32;
    // SAFETY: pidfd is a valid descriptor from pidfd_open.
    unsafe { libc::close(pidfd) };
    if dup < 0 { None } else { Some(dup) }
}

/// Read an integer socket option (SOL_SOCKET level).
fn get_sockopt_int(fd: RawFd, opt: libc::c_int) -> std::io::Result<i32> {
    let mut val: libc::c_int = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt with valid pointers to stack locals.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &mut val as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(val)
}

/// connect(2) on a supervisor-owned fd with the snapshot sockaddr.
fn connect_snapshot(fd: RawFd, snapshot: &[u8]) -> std::io::Result<()> {
    // SAFETY: connect with the snapshot buffer as the sockaddr; the
    // kernel applies its own family/length validation.
    let ret = unsafe {
        libc::connect(
            fd,
            snapshot.as_ptr() as *const libc::sockaddr,
            snapshot.len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The peer's bound address for a connected AF_UNIX socket, as
/// reported by the kernel (the listener's bind()-time literal).
fn unix_peer(fd: RawFd) -> Option<UnixSockaddr> {
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    // SAFETY: getpeername with a zeroed sockaddr_un and its size.
    let ret = unsafe { libc::getpeername(fd, &mut sa as *mut _ as *mut libc::sockaddr, &mut len) };
    if ret != 0 {
        return None;
    }
    let path_len = (len as usize).saturating_sub(2).min(sa.sun_path.len());
    // SAFETY: sun_path is a fixed-size array; path_len is bounded by
    // the kernel-returned address length and the array size.
    let bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(sa.sun_path.as_ptr().cast::<u8>(), path_len) };
    Some(parse_unix_path_bytes(bytes))
}

/// Parse an INET/INET6 sockaddr from the snapshot bytes, using the
/// fd's domain (kernel truth) to select the layout.
fn snapshot_inet_info(snapshot: &[u8], domain: i32) -> Option<SockaddrInfo> {
    match domain {
        libc::AF_INET if snapshot.len() >= std::mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: read_unaligned from a length-checked byte slice.
            let sa: libc::sockaddr_in =
                unsafe { std::ptr::read_unaligned(snapshot.as_ptr() as *const libc::sockaddr_in) };
            let port = u16::from_be(sa.sin_port);
            let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            Some(SockaddrInfo {
                family: libc::AF_INET as u16,
                destination: format!("{ip}:{port}"),
                port,
            })
        }
        libc::AF_INET6 if snapshot.len() >= std::mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: read_unaligned from a length-checked byte slice.
            let sa: libc::sockaddr_in6 =
                unsafe { std::ptr::read_unaligned(snapshot.as_ptr() as *const libc::sockaddr_in6) };
            let port = u16::from_be(sa.sin6_port);
            let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
            Some(SockaddrInfo {
                family: libc::AF_INET6 as u16,
                destination: format!("[{ip}]:{port}"),
                port,
            })
        }
        _ => None,
    }
}

/// Emit a `unix_socket_blocked` NDJSON audit line. Called BEFORE the
/// notification response so a crash between the two cannot skip the
/// record.
fn audit_unix_blocked(
    audit_fd: RawFd,
    dropped: &std::sync::Arc<std::sync::atomic::AtomicU64>,
    pid: u32,
    path: &str,
    reason: &str,
) {
    write_audit_line(
        audit_fd,
        dropped,
        &format!(
            "{{\"type\":\"unix_socket_blocked\",\"pid\":{pid},\"path\":\"{}\",\"syscall\":\"connect\",\"reason\":\"{reason}\"}}",
            escape_for_audit(path),
        ),
    );
}

/// Outcome of installing a verified private socket into the target.
enum DeliverOutcome {
    /// The fd was installed; the caller must still send the syscall
    /// response.
    Delivered,
    /// The notification went stale (target exited); no response
    /// should be sent.
    Stale,
    /// The ADDFD ioctl failed while the notification was valid.
    Failed,
}

/// Install the verified private socket at the target's fd number via
/// `SECCOMP_IOCTL_NOTIF_ADDFD` (SETFD), restoring the target's
/// `O_NONBLOCK` disposition and `FD_CLOEXEC` state on it. Takes
/// ownership of `private` (closed on every path — the kernel holds
/// its own reference after a successful install).
/// Peer verification and delivery for a dialed private socket: the
/// kernel-returned bind() literal of whatever the private socket
/// actually connected to, checked against the deny roots, then the
/// verified socket installed into the target. Shared by the absolute-
/// and relative-path dial paths.
#[allow(clippy::too_many_arguments)]
fn verify_and_deliver(
    listener_fd: RawFd,
    notif: &libc::seccomp_notif,
    private: RawFd,
    audit_fd: RawFd,
    config: &UnotifyConfig,
    dropped: &std::sync::Arc<std::sync::atomic::AtomicU64>,
    pid: u32,
    orig_status_flags: i32,
    orig_fd_flags: i32,
    sockfd: libc::c_int,
) -> bool {
    match unix_peer(private) {
        Some(UnixSockaddr::Path(peer)) => {
            if peer_denied(&peer, &config.unix_deny_roots) {
                let peer = peer.clone();
                // SAFETY: private is a valid fd owned here.
                unsafe { libc::close(private) };
                audit_unix_blocked(audit_fd, dropped, pid, &peer, "deny-root");
                return respond_errno(listener_fd, notif, libc::EACCES);
            }
        }
        Some(UnixSockaddr::Abstract(_) | UnixSockaddr::Unnamed) => {
            // Abstract/unnamed peers never match deny roots.
        }
        Some(UnixSockaddr::Unterminated) => {
            // Structurally odd peer address: fail closed.
            // SAFETY: private is a valid fd owned here.
            unsafe { libc::close(private) };
            audit_unix_blocked(audit_fd, dropped, pid, "", "peer-unterminated");
            return respond_errno(listener_fd, notif, libc::EACCES);
        }
        None => {
            // SAFETY: private is a valid fd owned here.
            unsafe { libc::close(private) };
            audit_unix_blocked(audit_fd, dropped, pid, "", "getpeername-failed");
            return respond_errno(listener_fd, notif, libc::EACCES);
        }
    }

    // Deliver: install the verified socket, respond val=0. Ownership
    // of `private` transfers to install_delivered_fd.
    match install_delivered_fd(
        listener_fd,
        notif,
        private,
        orig_status_flags,
        orig_fd_flags,
        sockfd as u32,
    ) {
        DeliverOutcome::Delivered => respond_val(listener_fd, notif, 0),
        DeliverOutcome::Stale => false,
        DeliverOutcome::Failed => {
            audit_unix_blocked(audit_fd, dropped, pid, "", "addfd-failed");
            respond_errno(listener_fd, notif, libc::EACCES)
        }
    }
}

fn install_delivered_fd(
    listener_fd: RawFd,
    notif: &libc::seccomp_notif,
    private: RawFd,
    orig_status_flags: i32,
    orig_fd_flags: i32,
    target_fd: u32,
) -> DeliverOutcome {
    // Restore the target's blocking disposition: the private socket
    // was created SOCK_NONBLOCK for the dial.
    // SAFETY: fcntl on a valid fd.
    let cur = unsafe { libc::fcntl(private, libc::F_GETFL) };
    if cur >= 0 {
        let want = (cur & !libc::O_NONBLOCK) | (orig_status_flags & libc::O_NONBLOCK);
        if want != cur {
            // SAFETY: fcntl on a valid fd.
            unsafe { libc::fcntl(private, libc::F_SETFL, want) };
        }
    }
    let newfd_flags: u32 = if orig_fd_flags & libc::FD_CLOEXEC != 0 {
        libc::O_CLOEXEC as u32
    } else {
        0
    };

    if !notif_id_valid(listener_fd, notif.id) {
        // SAFETY: private is a valid fd owned by this function.
        unsafe { libc::close(private) };
        return DeliverOutcome::Stale;
    }

    let addfd = SeccompNotifAddfd {
        id: notif.id,
        flags: SECCOMP_ADDFD_FLAG_SETFD,
        srcfd: private as u32,
        newfd: target_fd,
        newfd_flags,
    };
    // SAFETY: ioctl with a valid struct pointer on the listener fd.
    let ret = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd) };
    // SAFETY: private is a valid fd owned by this function; after a
    // successful ADDFD the kernel holds its own reference.
    unsafe { libc::close(private) };
    if ret < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ENOENT {
            return DeliverOutcome::Stale;
        }
        return DeliverOutcome::Failed;
    }
    DeliverOutcome::Delivered
}

/// Shared state for the connect-completion helper thread.
struct ConnectHelper {
    listener_fd: RawFd,
    audit_fd: RawFd,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    notif: libc::seccomp_notif,
    private: RawFd,
    orig_status_flags: i32,
    orig_fd_flags: i32,
    target_fd: u32,
}

impl ConnectHelper {
    fn finish(&self, result: std::io::Result<()>) -> bool {
        match result {
            Ok(()) => match install_delivered_fd(
                self.listener_fd,
                &self.notif,
                self.private,
                self.orig_status_flags,
                self.orig_fd_flags,
                self.target_fd,
            ) {
                DeliverOutcome::Delivered => respond_val(self.listener_fd, &self.notif, 0),
                DeliverOutcome::Stale => false,
                DeliverOutcome::Failed => {
                    audit_unix_blocked(
                        self.audit_fd,
                        &self.dropped,
                        self.notif.pid,
                        "",
                        "addfd-failed",
                    );
                    respond_errno(self.listener_fd, &self.notif, libc::EACCES)
                }
            },
            Err(e) => {
                // SAFETY: private is a valid fd owned by this helper.
                unsafe { libc::close(self.private) };
                respond_errno(
                    self.listener_fd,
                    &self.notif,
                    e.raw_os_error().unwrap_or(libc::EACCES),
                )
            }
        }
    }

    /// Wait (unbounded, matching blocking-connect semantics) for the
    /// connect to complete, then deliver.
    fn run(self) {
        let mut pfd = libc::pollfd {
            fd: self.private,
            events: libc::POLLOUT,
            revents: 0,
        };
        loop {
            // SAFETY: poll on a valid fd.
            let ret = unsafe { libc::ppoll(&mut pfd, 1, std::ptr::null_mut(), std::ptr::null()) };
            if ret >= 0 {
                break;
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                // Pathological poll failure: fail closed.
                let _ = self.finish(Err(std::io::Error::from_raw_os_error(libc::EACCES)));
                return;
            }
        }
        let result = match get_sockopt_int(self.private, libc::SO_ERROR) {
            Ok(0) => Ok(()),
            Ok(e) => Err(std::io::Error::from_raw_os_error(e)),
            Err(e) => Err(e),
        };
        let _ = self.finish(result);
    }
}

/// The connect() broker. See the section comment for the security
/// rationale. Returns true if a response was sent.
#[allow(clippy::too_many_arguments)]
fn broker_connect(
    listener_fd: RawFd,
    notif: &libc::seccomp_notif,
    mem: Option<&MemFd>,
    audit_fd: RawFd,
    config: &UnotifyConfig,
    dropped: &std::sync::Arc<std::sync::atomic::AtomicU64>,
    sockfd: u64,
    addr: u64,
    addrlen: u64,
) -> bool {
    use std::sync::atomic::Ordering;

    let pid = notif.pid;

    // Fail-closed: any inability to inspect the target denies.
    let Some(mem) = mem else {
        audit_unix_blocked(audit_fd, dropped, pid, "", "mem-open-failed");
        return respond_errno(listener_fd, notif, libc::EACCES);
    };

    // Notifications report the connecting thread's id; pidfd_open
    // only accepts thread-group leaders.
    let Some(tgid) = resolve_tgid(pid) else {
        audit_unix_blocked(audit_fd, dropped, pid, "", "tgid-resolve-failed");
        return respond_errno(listener_fd, notif, libc::EACCES);
    };

    if addr == 0 || addrlen < 2 {
        // Structurally invalid connect: same answer the kernel gives.
        return respond_errno(listener_fd, notif, libc::EINVAL);
    }
    let Some(snapshot) = read_sockaddr_snapshot(mem, addr, addrlen) else {
        audit_unix_blocked(audit_fd, dropped, pid, "", "sockaddr-read-failed");
        return respond_errno(listener_fd, notif, libc::EACCES);
    };

    let Some(dup) = dup_target_fd(tgid, sockfd) else {
        audit_unix_blocked(audit_fd, dropped, pid, "", "pidfd-getfd-failed");
        return respond_errno(listener_fd, notif, libc::EACCES);
    };
    // From here on, `dup` must be closed on every exit path.

    // fd identity: the kernel's answer for the pinned file
    // description, not the sockaddr buffer's family field.
    let domain = match get_sockopt_int(dup, libc::SO_DOMAIN) {
        Ok(d) => d,
        Err(e) => {
            // SAFETY: dup is a valid fd from pidfd_getfd.
            unsafe { libc::close(dup) };
            if e.raw_os_error() == Some(libc::ENOTSOCK) {
                // Target-visible failure, not a policy bypass.
                return respond_errno(listener_fd, notif, libc::ENOTSOCK);
            }
            audit_unix_blocked(audit_fd, dropped, pid, "", "getsockopt-failed");
            return respond_errno(listener_fd, notif, libc::EACCES);
        }
    };
    let so_type = match get_sockopt_int(dup, libc::SO_TYPE) {
        Ok(t) => t,
        Err(_) => {
            // SAFETY: dup is a valid fd from pidfd_getfd.
            unsafe { libc::close(dup) };
            audit_unix_blocked(audit_fd, dropped, pid, "", "getsockopt-failed");
            return respond_errno(listener_fd, notif, libc::EACCES);
        }
    };
    // SAFETY: fcntl on a valid fd.
    let orig_status_flags = unsafe { libc::fcntl(dup, libc::F_GETFL) };
    // FD_CLOEXEC is per-descriptor, and pidfd_getfd always creates its
    // copy with CLOEXEC set — reading it from `dup` would report the
    // supervisor's flag, not the target's, so the delivered socket
    // would always carry O_CLOEXEC and the target's inheritance
    // expectations break across its own execve. Read the target's
    // real flag from its fdinfo instead (openat/read are in the
    // allowlist and the supervisor already holds ptrace access).
    let orig_fd_flags = match target_fd_cloexec(pid, sockfd) {
        Some(cloexec) if cloexec => libc::FD_CLOEXEC,
        Some(_) => 0,
        None => {
            // Unreadable fdinfo: keep the conservative CLOEXEC (the
            // kernel default for pidfd_getfd) rather than deny the
            // connect over an fd-info hiccup.
            libc::FD_CLOEXEC
        }
    };
    if orig_status_flags < 0 {
        // SAFETY: dup is a valid fd from pidfd_getfd.
        unsafe { libc::close(dup) };
        audit_unix_blocked(audit_fd, dropped, pid, "", "fcntl-failed");
        return respond_errno(listener_fd, notif, libc::EACCES);
    }

    // Only the families the emulation dials are supported. Other
    // families (AF_NETLINK, AF_PACKET, ...) are denied WITHOUT
    // attempting socket(): the supervisor's own seccomp allowlist
    // family-filters socket(), and an unplanned family would kill the
    // supervisor (taking every subsequent connect with it — deny by
    // ENOSYS, but a self-inflicted single point of failure). CONTINUE
    // is not an option either: the fd-swap and buffer-rewrite races
    // would reach the AF_UNIX deny decision.
    if domain != libc::AF_UNIX && domain != libc::AF_INET && domain != libc::AF_INET6 {
        // SAFETY: dup is a valid fd from pidfd_getfd.
        unsafe { libc::close(dup) };
        audit_unix_blocked(audit_fd, dropped, pid, "", "family-unsupported");
        return respond_errno(listener_fd, notif, libc::EACCES);
    }

    // Private socket for the dial: same domain and type as the
    // target's socket, nonblocking for the connect. SO_PROTOCOL keeps
    // the protocol of the original socket (MPTCP/SCTP otherwise
    // degrade to plain TCP); SO_PEERCRED still reports the
    // supervisor's pid — documented in the README.
    // SAFETY: socket(2) with a family/type read from the pinned fd;
    // the domain is one of the allowlisted families checked above.
    let so_protocol = get_sockopt_int(dup, libc::SO_PROTOCOL).ok();
    let private = unsafe {
        libc::socket(
            domain,
            so_type | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            so_protocol.unwrap_or(0),
        )
    };
    if private < 0 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EACCES);
        // SAFETY: dup is a valid fd from pidfd_getfd.
        unsafe { libc::close(dup) };
        audit_unix_blocked(audit_fd, dropped, pid, "", "socket-failed");
        return respond_errno(listener_fd, notif, errno);
    }

    let close_both = |private: RawFd| {
        // SAFETY: both fds are valid and owned by this closure call.
        unsafe {
            libc::close(dup);
            libc::close(private);
        }
    };

    if domain == libc::AF_UNIX {
        // Validate the sockaddr structurally (the snapshot's family
        // field is NOT consulted — the kernel does not reliably
        // check it for AF_UNIX either; the fd's domain decides).
        if snapshot.len() < 3 {
            close_both(private);
            return respond_errno(listener_fd, notif, libc::EINVAL);
        }
        let mut unix_addr = parse_unix_path_bytes(&snapshot[2..]);
        if matches!(unix_addr, UnixSockaddr::Unterminated) {
            // glibc's SUN_LEN(), socat and ncat all pass
            // addrlen = 2 + strlen(path) with no trailing NUL; the
            // kernel's unix_mkname_bsd appends it and the connect
            // succeeds. Rejecting what the kernel accepts fails
            // those clients under the policy, so rebuild the address
            // with the terminator added. The peer check below is the
            // security control, not the request bytes.
            if snapshot.len() > 1 + std::mem::size_of::<libc::sockaddr_un>() {
                close_both(private);
                return respond_errno(listener_fd, notif, libc::ENAMETOOLONG);
            }
            // Parse from a terminated COPY, but dial with the
            // ORIGINAL snapshot: a 108-character path with no NUL is
            // exactly addrlen 110, which the kernel accepts — adding
            // the terminator would make the dial's sockaddr 111
            // bytes and fail with EINVAL. The terminator is for
            // parsing, not for connect().
            let mut terminated = snapshot.clone();
            terminated.push(0);
            // Re-parse: an unterminated RELATIVE path (socat or ncat
            // after a chdir) must reach the /proc/<tgid>/cwd rewrite
            // below as a Path, not stay Unterminated and be resolved
            // against the supervisor's working directory.
            unix_addr = parse_unix_path_bytes(&terminated[2..]);
        }

        // The kernel resolves a relative sun_path against the
        // CALLER's working directory — here that would be the
        // supervisor's, which never chdir'd from the launch
        // directory. A target that chdir'd and connects relatively
        // (the standard workaround for the 108-byte limit) would
        // reach the wrong socket or ENOENT. Rewrite the path against
        // the caller's /proc/<tgid>/cwd before dialing. The peer
        // check still applies to whatever the private socket
        // actually connects to, so this fixes reachability, not
        // policy.
        if let UnixSockaddr::Path(path) = &unix_addr {
            if !path.starts_with('/') {
                let rewritten = format!("/proc/{tgid}/cwd/{path}");
                if rewritten.len() + 3 > std::mem::size_of::<libc::sockaddr_un>() {
                    close_both(private);
                    return respond_errno(listener_fd, notif, libc::ENAMETOOLONG);
                }
                let mut addr_un: libc::sockaddr_un = unsafe { std::mem::zeroed() };
                addr_un.sun_family = libc::AF_UNIX as libc::sa_family_t;
                // SAFETY: rewritten is shorter than sun_path by the
                // length check above; copy then NUL is already zeroed.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        rewritten.as_ptr(),
                        addr_un.sun_path.as_mut_ptr().cast(),
                        rewritten.len(),
                    );
                }
                let full = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
                // SAFETY: connect with the rebuilt sockaddr.
                let ret = unsafe {
                    libc::connect(
                        private,
                        &addr_un as *const libc::sockaddr_un as *const libc::sockaddr,
                        full,
                    )
                };
                if ret != 0 {
                    let errno = std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EACCES);
                    close_both(private);
                    return respond_errno(listener_fd, notif, errno);
                }
                // Peer verification + delivery, same as the absolute
                // path below. `dup` (the pidfd_getfd copy) is closed
                // here: verify_and_deliver owns only `private`, and
                // leaking one descriptor per brokered connect drives
                // the supervisor into EMFILE mid-run.
                // SAFETY: dup is a valid fd owned by this call path.
                unsafe { libc::close(dup) };
                return verify_and_deliver(
                    listener_fd,
                    notif,
                    private,
                    audit_fd,
                    config,
                    dropped,
                    pid,
                    orig_status_flags,
                    orig_fd_flags,
                    sockfd as libc::c_int,
                );
            }
        }

        // Dial. AF_UNIX connects complete or fail immediately
        // (EAGAIN on a full backlog); there is no EINPROGRESS for
        // UDS.
        if let Err(e) = connect_snapshot(private, &snapshot) {
            let errno = e.raw_os_error().unwrap_or(libc::EACCES);
            close_both(private);
            // Dial failures are target-visible (ENOENT, ECONNREFUSED,
            // EAGAIN, EPROTOTYPE, EAFNOSUPPORT, ...) — pass through.
            return respond_errno(listener_fd, notif, errno);
        }

        // SAFETY: dup is a valid fd owned by this call path; closed
        // here for the same EMFILE reason as the relative branch.
        unsafe { libc::close(dup) };
        return verify_and_deliver(
            listener_fd,
            notif,
            private,
            audit_fd,
            config,
            dropped,
            pid,
            orig_status_flags,
            orig_fd_flags,
            sockfd as libc::c_int,
        );
    }

    // INET families: apply the existing bridge/enforce policy to the
    // snapshot BEFORE dialing — the supervisor only dials allowed
    // targets.
    if domain == libc::AF_INET || domain == libc::AF_INET6 {
        match snapshot_inet_info(&snapshot, domain) {
            Some(info) => {
                if !is_bridge_addr(&info, config) {
                    if config.audit_network {
                        write_audit_line(
                            audit_fd,
                            dropped,
                            &format!(
                                "{{\"type\":\"network_blocked\",\"pid\":{pid},\"dest\":\"{}\",\"syscall\":\"connect\"}}",
                                escape_for_audit(&info.destination),
                            ),
                        );
                    }
                    if config.enforce_network {
                        close_both(private);
                        return respond_errno(listener_fd, notif, libc::ECONNREFUSED);
                    }
                }
            }
            None => {
                // Malformed INET sockaddr.
                close_both(private);
                return respond_errno(listener_fd, notif, libc::EINVAL);
            }
        }
    }

    // Dial (INET may return EINPROGRESS; other families pass
    // through with whatever the kernel says).
    match connect_snapshot(private, &snapshot) {
        Ok(()) => {
            // SAFETY: dup is a valid fd; private ownership transfers.
            unsafe { libc::close(dup) };
            match install_delivered_fd(
                listener_fd,
                notif,
                private,
                orig_status_flags,
                orig_fd_flags,
                sockfd as u32,
            ) {
                DeliverOutcome::Delivered => respond_val(listener_fd, notif, 0),
                DeliverOutcome::Stale => false,
                DeliverOutcome::Failed => {
                    audit_unix_blocked(audit_fd, dropped, pid, "", "addfd-failed");
                    respond_errno(listener_fd, notif, libc::EACCES)
                }
            }
        }
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {
            if orig_status_flags & libc::O_NONBLOCK != 0 {
                // Nonblocking socket: POSIX result is EINPROGRESS and
                // the target polls on the delivered socket.
                // SAFETY: dup is a valid fd; private ownership transfers.
                unsafe { libc::close(dup) };
                return match install_delivered_fd(
                    listener_fd,
                    notif,
                    private,
                    orig_status_flags,
                    orig_fd_flags,
                    sockfd as u32,
                ) {
                    DeliverOutcome::Delivered => {
                        respond_errno(listener_fd, notif, libc::EINPROGRESS)
                    }
                    DeliverOutcome::Stale => false,
                    DeliverOutcome::Failed => {
                        audit_unix_blocked(audit_fd, dropped, pid, "", "addfd-failed");
                        respond_errno(listener_fd, notif, libc::EACCES)
                    }
                };
            }
            // Blocking socket: wait for completion on a helper thread
            // so the supervisor loop never stalls.
            // SAFETY: dup is a valid fd; private ownership transfers
            // to the helper.
            unsafe { libc::close(dup) };
            if active_connect_helpers().load(Ordering::Relaxed) >= MAX_CONNECT_HELPERS {
                // SAFETY: private is a valid fd.
                unsafe { libc::close(private) };
                audit_unix_blocked(audit_fd, dropped, pid, "", "helper-cap");
                return respond_errno(listener_fd, notif, libc::EAGAIN);
            }
            let helper = ConnectHelper {
                listener_fd,
                audit_fd,
                dropped: std::sync::Arc::clone(dropped),
                notif: *notif,
                private,
                orig_status_flags,
                orig_fd_flags,
                target_fd: sockfd as u32,
            };
            active_connect_helpers().fetch_add(1, Ordering::Relaxed);
            match std::thread::Builder::new()
                .name("connect-helper".into())
                .spawn(move || {
                    helper.run();
                    active_connect_helpers().fetch_sub(1, Ordering::Relaxed);
                }) {
                // The helper owns the response.
                Ok(_handle) => true,
                Err(_) => {
                    active_connect_helpers().fetch_sub(1, Ordering::Relaxed);
                    // SAFETY: private is a valid fd.
                    unsafe { libc::close(private) };
                    audit_unix_blocked(audit_fd, dropped, pid, "", "helper-spawn-failed");
                    respond_errno(listener_fd, notif, libc::EACCES)
                }
            }
        }
        Err(e) => {
            let errno = e.raw_os_error().unwrap_or(libc::EACCES);
            close_both(private);
            respond_errno(listener_fd, notif, errno)
        }
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

/// Wait (bounded) for the supervisor's listener-handover ack on the
/// parent end of the socketpair.
///
/// The supervisor writes one byte after successfully duplicating the
/// listener fd via pidfd_getfd, and closes the socketpair on every
/// path (ack, or death before the dup). Returns true only when the
/// ack byte arrived; false on timeout, EOF (supervisor exited), or
/// error. The caller decides between fail-closed (UDS connect policy
/// active) and lenient continuation (audit-only features).
pub fn wait_fd_ack(socketpair_parent: RawFd, timeout_ms: i32) -> bool {
    wait_fd_ack_outcome(socketpair_parent, timeout_ms) == AckOutcome::Acked
}

/// How the listener-handover wait ended.
///
/// A timeout and a dead supervisor both mean "no ack", but they call
/// for different reports: one is a stall that may still resolve, the
/// other can never resolve. Collapsing them turns a supervisor that
/// exited into a five-second silence followed by a message about
/// timeouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    /// The supervisor duplicated the listener and acked.
    Acked,
    /// The socketpair reached EOF: the supervisor exited without
    /// acking, so waiting longer cannot help.
    SupervisorGone,
    /// The deadline passed with the socketpair still open.
    TimedOut,
}

/// Wait (bounded) for the supervisor's listener-handover ack, saying
/// why the wait ended. See [`wait_fd_ack`].
pub fn wait_fd_ack_outcome(socketpair_parent: RawFd, timeout_ms: i32) -> AckOutcome {
    let mut pfd = libc::pollfd {
        fd: socketpair_parent,
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = loop {
        // SAFETY: poll on a valid socketpair end.
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break ret;
        }
    };
    if ret == 0 {
        return AckOutcome::TimedOut;
    }
    if ret < 0 {
        return AckOutcome::SupervisorGone;
    }
    // A supervisor that acks and then exits reports POLLIN together
    // with POLLHUP, so a readable descriptor wins over the hangup: the
    // byte is the ack, the hangup is just the close that follows it.
    if pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) & libc::POLLIN != 0 {
        let mut ack = [0u8; 1];
        // SAFETY: read of one byte from the polled socketpair end.
        let n = unsafe { libc::read(socketpair_parent, ack.as_mut_ptr().cast(), 1) };
        return match n {
            1 => AckOutcome::Acked,
            // EOF: the supervisor closed without acking, so no ack can
            // follow.
            0 => AckOutcome::SupervisorGone,
            _ => AckOutcome::SupervisorGone,
        };
    }
    AckOutcome::SupervisorGone
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
/// were drops, flushes a summary line. The counter is atomic: helper
/// threads emit audit lines concurrently with the supervisor loop.
fn write_audit_line(
    audit_fd: RawFd,
    dropped: &std::sync::Arc<std::sync::atomic::AtomicU64>,
    line: &str,
) {
    use std::sync::atomic::Ordering;
    // Policy-only runs have no audit pipe (fd -1): events are
    // discarded rather than written to a bad fd.
    if audit_fd < 0 {
        return;
    }
    // Flush drop summary if there were previous drops. swap(0) takes
    // the count and resets it in one step: load-then-store loses any
    // drop counted between the two, which is exactly the traffic this
    // summary exists to account for.
    let pending = dropped.swap(0, Ordering::Relaxed);
    if pending > 0 {
        let summary = format!("{{\"type\":\"dropped\",\"count\":{pending}}}\n");
        let ret = unsafe { libc::write(audit_fd, summary.as_ptr().cast(), summary.len()) };
        if ret <= 0 {
            // The write failed; keep the count for the next flush
            // instead of losing the drops silently.
            dropped.fetch_add(pending, Ordering::Relaxed);
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
        dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let data = format!("{line}\n");
    let ret = unsafe { libc::write(audit_fd, data.as_ptr().cast(), data.len()) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ─── Supervisor loop ──────────────────────────────────────────────

/// How the supervisor loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopExit {
    /// The listener was destroyed (target exited) or closed — the
    /// normal end of a run.
    ListenerClosed,
    /// Any other receive error — the listener may still be alive
    /// while nothing is serving it.
    Error,
}

/// Main notification processing loop. Runs in the supervisor child.
///
/// Loops on `notif_recv()`, dispatches each notification to
/// `handle_notification()`, and returns when the listener FD becomes
/// invalid. The caller decides what happens next: the legacy
/// child-topology supervisor `_exit`s; the supervisor-mode parent
/// applies the kill-or-wait rule and reaps the wrapper.
pub fn supervisor_loop(
    listener_fd: RawFd,
    audit_fd: RawFd,
    config: &UnotifyConfig,
    child_pid: Option<i32>,
) -> LoopExit {
    use std::sync::atomic::Ordering;
    let dropped: std::sync::Arc<std::sync::atomic::AtomicU64> =
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Watch the wrapper (parent topology): a USER_NOTIF filter is
    // refcounted per task, so notif_recv returns ENOENT only when
    // the LAST task carrying it exits. If the target forks a child
    // and exits, a purely listener-driven loop blocks until that
    // descendant dies — wedging the run and defeating --timeout.
    // Polling a pidfd on the wrapper ends the loop at wrapper
    // death; surviving descendants lose broker services (their
    // intercepted syscalls fail closed) and are swept by the
    // launcher's process-group kill. The legacy topology passes
    // None — its supervisor dies with the wrapper via PDEATHSIG.
    let pidfd: i32 = child_pid
        .map(|pid| unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32)
        .unwrap_or(-1);

    let mut exit = LoopExit::ListenerClosed;
    loop {
        // Subreaper duty: reap adopted descendants (zombies of
        // processes that re-parented to this supervisor), or they
        // accumulate for the wrapper's whole lifetime. The wrapper
        // itself is NOT reaped here — its status belongs to the
        // post-loop waitpid — so peek with WNOWAIT and stop at it.
        loop {
            let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: waitid P_ALL, non-blocking, no-reap peek.
            let ret = unsafe {
                libc::waitid(
                    libc::P_ALL,
                    0,
                    &mut si,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            let pid = unsafe { si.si_pid() };
            if ret != 0 || pid == 0 {
                break;
            }
            if child_pid == Some(pid) {
                break;
            }
            let mut st: libc::c_int = 0;
            // SAFETY: waitpid on the specific adopted child.
            unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
        }

        let mut fds = [
            libc::pollfd {
                fd: listener_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pidfd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n_fds = if pidfd >= 0 { 2 } else { 1 };
        // A 250 ms timeout, not an infinite wait: adopted descendants
        // (subreaper duty) become zombies that ppoll never wakes for —
        // SIGCHLD is ignored by default — and under the connect policy
        // alone, notifications can be rare enough that zombies pile up
        // against pids.max and RLIMIT_NPROC for the wrapper's whole
        // lifetime. The periodic wake runs the loop-top reaper.
        let mut poll_timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 250_000_000,
        };
        // SAFETY: ppoll with a valid pollfd array, a stack timespec,
        // and no signal-mask manipulation.
        let ready = unsafe {
            libc::ppoll(
                fds.as_mut_ptr(),
                n_fds,
                &mut poll_timeout as *mut libc::timespec,
                std::ptr::null(),
            )
        };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            log::warn!("unotify supervisor: ppoll: {err}");
            exit = LoopExit::Error;
            break;
        }
        if pidfd >= 0 && fds[1].revents != 0 {
            // The wrapper died. Confirm WITHOUT reaping (WNOWAIT) —
            // the post-loop waitpid still owns the exit status.
            let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: waitid with WEXITED|WNOHANG|WNOWAIT on our
            // direct child.
            let ret = unsafe {
                libc::waitid(
                    libc::P_PID,
                    child_pid.unwrap() as libc::id_t,
                    &mut si,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if ret == 0 && unsafe { si.si_pid() } != 0 {
                break;
            }
            // Not a confirmed exit — keep serving the listener.
        }
        // The filter is orphaned (every task carrying it exited) when
        // the listener hangs up with nothing left to read — and this
        // must be decided BEFORE calling recv: on kernels before 6.6
        // NOTIF_RECV blocks in down_interruptible even when the filter
        // has no users left, so a recv entered on a POLLHUP-only
        // listener never returns (pidns mode hits this: the relay
        // reaps the pid-1 target, the listener hangs up, the relay's
        // pidfd has not fired yet). POLLHUP arrives together with a
        // trailing POLLIN notification in the normal single-target
        // case, so only the no-POLLIN form ends the loop.
        if fds[0].revents & libc::POLLIN == 0
            && fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0
        {
            break;
        }
        if fds[0].revents & libc::POLLIN != 0 {
            match notif_recv(listener_fd) {
                Ok(notif) => {
                    handle_notification(listener_fd, &notif, audit_fd, config, &dropped);
                }
                Err(e) => {
                    let errno = e.raw_os_error().unwrap_or(0);
                    // EINTR and ENOENT both mean "no notification this
                    // time, keep going": ENOENT is returned not only
                    // when the filter is destroyed but when the
                    // target's blocked syscall was interrupted by a
                    // signal handler — the notification is withdrawn
                    // while the target lives (seccomp_user_notif(2);
                    // observed 1-2 per ~5000 notifications under a
                    // signal storm on 6.18). Treating that as
                    // "filter destroyed" ends the loop while the
                    // wrapper still runs, and every later intercepted
                    // syscall then blocks forever on a listener nobody
                    // reads.
                    if errno == libc::EINTR || errno == libc::ENOENT {
                        // A withdrawn notification: retry the recv.
                        continue;
                    }
                    // EBADF: listener FD closed. Normal exit.
                    if errno != libc::EBADF {
                        log::warn!("unotify supervisor: recv error: {e}");
                        exit = LoopExit::Error;
                    }
                    break;
                }
            }
        }
    }
    if pidfd >= 0 {
        // SAFETY: pidfd is a valid descriptor or already closed.
        unsafe { libc::close(pidfd) };
    }

    // Flush final drop count.
    let dropped = dropped.load(Ordering::Relaxed);
    if dropped > 0 {
        let summary = format!("{{\"type\":\"dropped\",\"count\":{dropped}}}\n");
        let _ = unsafe { libc::write(audit_fd, summary.as_ptr().cast(), summary.len()) };
    }

    exit
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

static ADDFD_AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Check if the kernel supports `SECCOMP_IOCTL_NOTIF_ADDFD`
/// (kernel ≥ 5.9), required by the connect broker's socket delivery.
///
/// Probed independently of [`unotify_available`] — audit-only
/// features work on 5.5+ kernels without ADDFD; the UDS connect
/// policy does not, and must fail closed when it is missing.
pub fn addfd_available() -> bool {
    *ADDFD_AVAILABLE.get_or_init(probe_addfd_support)
}

fn probe_addfd_support() -> bool {
    // Install a USER_NOTIF filter in a clone child and issue an
    // ADDFD ioctl with a stale notification id: an unknown ioctl
    // returns ENOTTY (pre-5.9 kernel); a known one returns a stale-id
    // error instead. The filter must exist for the ioctl to be
    // meaningful on the listener fd.
    let bpf = match build_unotify_bpf(&[libc::SYS_getpid]) {
        Ok(b) => b,
        Err(_) => return false,
    };
    // SAFETY: fork with a pre-allocated BPF program; the child only
    // uses the inherited COW copy.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        // SAFETY: prctl with scalar arguments.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64) } != 0 {
            unsafe { libc::_exit(1) };
        }
        match install_unotify_filter(&bpf) {
            Ok(fd) => {
                let addfd = SeccompNotifAddfd {
                    // Stale id: can never match a live notification.
                    id: u64::MAX,
                    flags: 0,
                    srcfd: fd as u32,
                    newfd: 0,
                    newfd_flags: 0,
                };
                // SAFETY: ioctl on the listener fd returned above.
                let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd) };
                let errno = std::io::Error::last_os_error().raw_os_error();
                // "Supported" is the stale-id answer (ENOENT): the
                // ioctl exists and processed the request. ENOTTY is
                // the pre-5.9 unknown-ioctl answer, but seccomp's
                // ioctl dispatcher returns EINVAL for unknown
                // commands there too (measured on 6.18; the
                // dispatcher's default case), so EINVAL is also
                // "unsupported" — treating it as support would pass
                // the launch-time check and then fail every connect
                // at run time.
                let supported = ret < 0 && errno == Some(libc::ENOENT);
                // SAFETY: fd is a valid listener descriptor.
                unsafe { libc::close(fd) };
                unsafe { libc::_exit(if supported { 0 } else { 1 }) };
            }
            Err(_) => unsafe { libc::_exit(1) },
        }
    }
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
    ret > 0 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

fn probe_unotify_support() -> bool {
    // Phase 1: Check that the supervisor can read a descendant's
    // /proc/<pid>/mem — the relationship the parent topology uses.
    // This catches Yama ptrace_scope=3 (which denies even
    // parent→child) and Landlock/LSM restrictions.
    if !probe_proc_mem_access_parent_to_child() {
        log::info!("unotify: /proc/<pid>/mem access blocked (Landlock, Yama, or LSM restriction)");
        return false;
    }

    // Phase 2: Check that seccomp USER_NOTIF + CONTINUE works.
    probe_seccomp_unotify()
}

/// Availability for the legacy child topology (selfexec): the
/// supervisor is the target's child and must inspect its PARENT —
/// denied by Yama ptrace_scope >= 1 without a user namespace.
/// Own cache: the parent- and child-direction probes answer
/// different questions and must not poison each other's result
/// (on a Yama-1 host the plain probe caches `true` and would mask
/// the child-direction denial until run time).
static AVAILABLE_CHILD_TOPOLOGY: OnceLock<bool> = OnceLock::new();

pub fn unotify_available_child_topology() -> bool {
    *AVAILABLE_CHILD_TOPOLOGY
        .get_or_init(|| probe_proc_mem_access_child_to_parent() && probe_seccomp_unotify())
}

static AVAILABLE_USERNS: OnceLock<bool> = OnceLock::new();

/// Availability for a supervisor that will run INSIDE a user
/// namespace (netns-wrapped launches): it holds capabilities there,
/// so parent→child inspection works at Yama scopes 0-2 — only
/// scope 3 (unconditional deny) blocks it, which the sysctl
/// reports directly. Used by the launcher for netns runs, where
/// probing from outside the namespace (the plain-run probe) would
/// wrongly fail at scope 2.
pub fn unotify_available_in_userns() -> bool {
    *AVAILABLE_USERNS.get_or_init(|| yama_scope() < 3 && probe_seccomp_unotify())
}

/// The host's Yama ptrace_scope (0 when unreadable — permissive).
fn yama_scope() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn probe_proc_mem_access_parent_to_child() -> bool {
    // The supervisor (parent) reads its child's /proc/<pid>/mem —
    // permitted by Yama ptrace_scope 0 and 1 (descendant ptrace),
    // denied at 2 without caps and at 3 unconditionally.
    // SAFETY: single-threaded at probe time (called during launch).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        // Child: stay alive long enough to be probed.
        // SAFETY: nanosleep on a zeroed timespec.
        let ts = libc::timespec {
            tv_sec: 2,
            tv_nsec: 0,
        };
        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
        unsafe { libc::_exit(0) };
    }

    // Parent: try to open the child's /proc/<pid>/mem.
    let mem_path = format!("/proc/{pid}/mem");
    let ok = std::fs::File::open(&mem_path).is_ok();
    // SAFETY: kill + reap the probe child.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status: libc::c_int = 0;
        libc::waitpid(pid, &mut status, 0);
    }
    ok
}

fn probe_proc_mem_access_child_to_parent() -> bool {
    // The legacy child-topology relationship: the supervisor (a
    // child process) reads the target's (its parent's)
    // /proc/<pid>/mem. Under Yama ptrace_scope=1 this is blocked
    // without a user namespace.
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
    /// Broker connect() and deny privileged Unix sockets (the UDS
    /// connect policy). While active, connect() notifications are
    /// NEVER answered with CONTINUE: the supervisor dials a
    /// supervisor-private socket with a snapshot of the target's
    /// sockaddr, verifies the peer, and — when allowed — installs the
    /// verified socket into the target's fd table via
    /// `SECCOMP_IOCTL_NOTIF_ADDFD` (SETFD). The target's original
    /// socket is never connected, in any branch.
    pub enforce_unix_connect: bool,
    /// Deny roots for the UDS connect policy: the connection is
    /// denied when the peer's bound path (as reported by
    /// `getpeername`, i.e. the listener's bind()-time literal) equals
    /// a root or lies beneath it. Built-in roots plus operator
    /// additions, normalized by the launcher.
    pub unix_deny_roots: Vec<String>,
}

impl UnotifyConfig {
    pub fn any_enabled(&self) -> bool {
        self.audit_file_access || self.audit_network || self.enforce_unix_connect
    }
}

/// Built-in deny roots for the UDS connect policy.
///
/// Matched against the peer's bind()-time literal path
/// (component-wise, after `/var/run/` → `/run/` alias
/// normalization). `/run/user/<uid>/...` is deliberately absent:
/// rootless daemon sockets (e.g. rootless podman) live there and
/// must keep working. Unknown paths outside the roots remain
/// reachable by design — the list is the allow-by-default tradeoff
/// that keeps legitimate socket use working; operators extend it via
/// `unix_socket_deny_roots`.
pub fn builtin_unix_deny_roots() -> Vec<String> {
    [
        "/run/docker.sock",
        "/run/snap.docker.dockerd.sock",
        "/run/podman",
        "/run/containerd",
        "/run/crio",
        "/run/dbus",
        "/run/libvirt",
        "/run/systemd/private",
        "/run/lxd",
        "/var/lib/lxd/unix.socket",
        // Snap LXD: the daemon binds under /var/snap, group lxd —
        // root-equivalent on hosts where the user is in that group.
        "/var/snap/lxd/common/lxd",
        // Incus (the LXD fork): group incus-admin, same escape shape.
        "/var/lib/incus",
        "/run/incus",
        "/run/snapd.socket",
        "/run/snapd-snap.socket",
    ]
    .into_iter()
    .map(String::from)
    .collect()
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
        enforce_unix_connect: config.enforce_unix_connect,
        unix_deny_roots: config.unix_deny_roots.clone(),
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
        let wrapper_pid = i32::from_ne_bytes(msg[..4].try_into().unwrap());
        let remote_fd = i32::from_ne_bytes(msg[4..].try_into().unwrap());
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, wrapper_pid, 0i32) } as i32;
        if pidfd < 0 {
            crate::wrapper::write_stderr("unotify supervisor: pidfd_open failed\n");
            unsafe {
                libc::close(sp_child);
                libc::_exit(1);
            }
        }
        let listener_fd =
            unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, remote_fd, 0u32) } as i32;
        unsafe { libc::close(pidfd) };
        if listener_fd < 0 {
            crate::wrapper::write_stderr("unotify supervisor: pidfd_getfd failed\n");
            unsafe {
                libc::close(sp_child);
                libc::_exit(1);
            }
        }

        // Acknowledge the handover BEFORE the wrapper execs: the
        // listener fd is CLOEXEC on the wrapper side, so the dup must
        // win the race against execve or the filter loses its only
        // listener and every intercepted syscall returns ENOSYS. The
        // wrapper blocks on this ack; a supervisor that dies before
        // duplicating closes the socketpair without writing (EOF).
        unsafe {
            libc::write(sp_child, [1u8].as_ptr().cast(), 1);
            libc::close(sp_child);
        }

        // Enter the supervisor loop and exit with its historical
        // status (the legacy child's lifecycle is pdeathsig-managed;
        // there is nothing to reap).
        let _ = supervisor_loop(listener_fd, audit_write_fd, &child_config, None);
        unsafe { libc::_exit(0) };
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

// ─── Supervisor mode ───────────────────────────────────────────────
//
// The parent-topology entry point: the launcher spawns the arapuca
// binary in supervisor mode (inside the same `unshare` the wrapper
// would get), and this process forks + execs the wrapper as its own
// child. Yama ptrace_scope >= 1 permits ptrace only of descendants,
// so the supervisor inspecting its child needs no capabilities —
// unlike the legacy child topology, where the supervisor was the
// target's child and needed a user namespace to inspect its parent.
//
// argv: [arapuca, --supervisor, --, <cmd>...]
// env (all set by the launcher):
//   ARAPUCA_SUPERVISOR=1        sentinel (also checked by main)
//   ARAPUCA_WRAPPER_EXEC_FD=N   pinned wrapper binary fd (exec'd
//                               via /proc/self/fd/N — never a PATH
//                               lookup)
//   ARAPUCA_CGROUP_SYNC_FD=N    cgroup sync read end (consumed here,
//                               BEFORE the wrapper fork — the fork is
//                               the cgroup-membership inheritance
//                               point)
//   ARAPUCA_SUPERVISOR_TTY=1    tty run: make the wrapper's process
//                               group the terminal foreground group
//   ARAPUCA_UNOTIFY_CONFIG      the supervisor config (strict parse)
//   ARAPUCA_UNOTIFY_AUDIT_FD    the supervisor's audit pipe
//   ARAPUCA_SECCOMP_DEBUG       allowlist debug mode
// plus every ARAPUCA_* var the wrapper itself needs (passed through
// the exec unchanged, minus the two consumed here).

/// Run the supervisor-mode lifecycle. Never returns.
pub fn run_supervisor_mode(args: &[String]) -> ! {
    use crate::wrapper::write_stderr;

    // The command starts after the "--" that follows the marker.
    let cmd_start = args.iter().position(|a| a == "--").and_then(|i| {
        if i + 1 < args.len() {
            Some(i + 1)
        } else {
            None
        }
    });
    let Some(cmd_start) = cmd_start else {
        write_stderr("arapuca: supervisor: missing command after --\n");
        unsafe { libc::_exit(125) };
    };

    // 1. Die with the launcher. This is also the load-bearing
    //    defense against forged in-sandbox invocation: a sandboxed
    //    process exec'ing arapuca with a forged sentinel dies here
    //    (its inherited seccomp EPERMs the prctl).
    //
    // The parent is sampled BEFORE the prctl: if the launcher dies in
    // that window the signal never arrives, and comparing getppid()
    // with a value sampled afterwards would compare the call with
    // itself.
    let parent_pid = unsafe { libc::getppid() };
    // SAFETY: prctl with scalar arguments.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
        write_stderr("arapuca: supervisor: PR_SET_PDEATHSIG failed\n");
        unsafe { libc::_exit(1) };
    }
    if unsafe { libc::getppid() } != parent_pid {
        unsafe { libc::_exit(1) };
    }
    // 2. Not ptraceable by same-uid processes (exec resets this; the
    //    launcher's pre_exec value did not survive our own exec).
    // SAFETY: prctl with scalar arguments.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        write_stderr("arapuca: supervisor: PR_SET_DUMPABLE failed\n");
        unsafe { libc::_exit(1) };
    }

    // 3. Consume the cgroup sync byte BEFORE forking the wrapper:
    //    the launcher added THIS process to the cgroup and signaled
    //    readiness; the fork inherits membership from this point on,
    //    which closes the fork-before-add_pid race.
    if let Ok(fd_str) = std::env::var("ARAPUCA_CGROUP_SYNC_FD") {
        match fd_str.parse::<i32>() {
            Ok(fd) => {
                let mut buf = [0u8; 1];
                // SAFETY: read of one byte from the launcher's pipe.
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), 1) };
                // SAFETY: fd is a valid pipe end.
                unsafe { libc::close(fd) };
                if n != 1 {
                    write_stderr("arapuca: supervisor: cgroup sync failed\n");
                    unsafe { libc::_exit(1) };
                }
            }
            // The launcher writes this value, so a malformed one means
            // a launcher/supervisor mismatch. Skipping the handshake
            // silently would let the wrapper fork before the cgroup
            // membership is established, which is what the byte
            // exists to prevent.
            Err(_) => {
                write_stderr("arapuca: supervisor: invalid ARAPUCA_CGROUP_SYNC_FD\n");
                unsafe { libc::_exit(1) };
            }
        }
    }

    // 4. Socketpair for the listener handover. The child end must
    //    survive the exec into the wrapper (no CLOEXEC); the parent
    //    end is closed after the handover.
    let mut sv = [0i32; 2];
    // SAFETY: socketpair with a valid array.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        write_stderr(&format!(
            "arapuca: supervisor: socketpair: {}\n",
            std::io::Error::last_os_error()
        ));
        unsafe { libc::_exit(1) };
    }
    let sp_parent = sv[0];
    let sp_child = sv[1];

    // Become a child subreaper BEFORE forking the wrapper: on plain
    // Yama-1 runs the supervisor has no CAP_SYS_PTRACE and can only
    // inspect its own descendants. When an intermediate process
    // exits, its orphans re-parent to init or the user's systemd --
    // outside the supervisor's subtree -- and every later inspection
    // of them fails with EPERM. As a subreaper the supervisor adopts
    // them instead, keeping them inspectable (and swept) for the
    // wrapper's whole lifetime.
    // SAFETY: prctl with scalar arguments.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1i64) } != 0 {
        write_stderr("arapuca: supervisor: PR_SET_CHILD_SUBREAPER failed\n");
        unsafe { libc::_exit(1) };
    }

    // Forward terminal signals to the wrapper instead of dying to
    // them: the supervisor is the session's long-lived member now,
    // and systemd's KillMode=control-group TERMs every task in the
    // unit's cgroup subtree. Dying here PDEATHSIG-SIGKILLs the
    // wrapper before its own handler can finish a clean shutdown.
    // SA_RESTART keeps the loop's ppoll/waitpid from fragmenting.
    // SAFETY: sigaction with a valid handler and flags.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = supervisor_forward_signal as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }

    // The pinned wrapper fd: exec /proc/self/fd/N, clearing CLOEXEC
    // first (the launcher set it to survive only one hop).
    let wrapper_fd: i32 = match std::env::var("ARAPUCA_WRAPPER_EXEC_FD")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(fd) => fd,
        None => {
            write_stderr("arapuca: supervisor: ARAPUCA_WRAPPER_EXEC_FD not set\n");
            unsafe { libc::_exit(125) };
        }
    };
    let wrapper_path = format!("/proc/self/fd/{wrapper_fd}");

    // SAFETY: getpid is always safe. Sampled BEFORE the fork so the
    // child's pdeathsig race check compares against the real parent.
    let supervisor_pid = unsafe { libc::getpid() };
    // SAFETY: single-threaded at this point (fresh exec, no threads).
    let child_pid = unsafe { libc::fork() };
    WRAPPER_PID.store(child_pid, std::sync::atomic::Ordering::Release);
    if child_pid < 0 {
        write_stderr(&format!(
            "arapuca: supervisor: fork: {}\n",
            std::io::Error::last_os_error()
        ));
        unsafe { libc::_exit(1) };
    }

    // The pid report: with ARAPUCA_PID_NS the wrapper (and its
    // relay) owns the report — pass the fd through. Without it, this
    // supervisor is the writer: report the wrapper pid (its own
    // process-group leader), close, and strip from the child env.
    let pidns_mode = std::env::var("ARAPUCA_PID_NS").as_deref() == Ok("1");
    let pid_report_fd: Option<i32> = std::env::var("ARAPUCA_PID_REPORT_FD")
        .ok()
        .and_then(|s| s.parse().ok());
    // The WRITE is parent-branch only: a write from the fork child
    // would race four zero bytes (child_pid == 0) into the
    // launcher's 4-byte read and corrupt target_pid (pidfd,
    // --timeout, and the orphan sweep would all target the
    // supervisor instead of the wrapper).

    if child_pid == 0 {
        // ── Wrapper child ──────────────────────────────────────
        // SAFETY: close the parent's socketpair end.
        unsafe { libc::close(sp_parent) };
        // Plain mode: the supervisor owns the report pipe. Close
        // the inherited copy so it cannot leak into the wrapper and
        // target (in pidns mode the wrapper's relay is the writer
        // and keeps it).
        if let Some(fd) = pid_report_fd {
            if !pidns_mode {
                // SAFETY: fd is a valid pipe end in this fork child.
                unsafe { libc::close(fd) };
            }
        }
        // Clear CLOEXEC on the pinned wrapper fd so execve of
        // /proc/self/fd/N resolves.
        // SAFETY: fcntl on a valid fd.
        let flags = unsafe { libc::fcntl(wrapper_fd, libc::F_GETFD) };
        if flags >= 0 {
            // SAFETY: fcntl on a valid fd.
            unsafe { libc::fcntl(wrapper_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
        }

        // fork() clears the parent-death signal, and the wrapper only
        // re-arms it after exec, Rust startup, PATH lookup and
        // canonicalize — a window in which a dead supervisor leaves
        // an orphan that sails through its own ppid check. Re-arm
        // here, before the exec.
        // SAFETY: prctl with scalar arguments.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
            unsafe { libc::_exit(1) };
        }
        // SAFETY: getppid is always safe.
        if unsafe { libc::getppid() } != supervisor_pid {
            unsafe { libc::_exit(1) };
        }
        // Become our own SESSION leader (invariant 3, restored): the
        // wrapper must not live in the supervisor's session. On tty
        // runs it also takes the controlling terminal here — the
        // launcher skipped TIOCSCTTY for exactly this. The wrapper's
        // group is then orphaned (its parent, the supervisor, is in
        // another session), which is what makes the kernel discard
        // terminal stop signals for it: a SIGTSTP that stopped the
        // target would never be SIGCONT'd by anyone, wedging the run
        // until --timeout.
        // SAFETY: setsid on self; fails EPERM only if already a
        // session leader, which the parent's pre_exec setsid makes
        // impossible here.
        if unsafe { libc::setsid() } == -1 {
            write_stderr("arapuca: supervisor: child setsid failed\n");
            unsafe { libc::_exit(1) };
        }
        if std::env::var("ARAPUCA_SUPERVISOR_TTY").as_deref() == Ok("1") {
            // SAFETY: TIOCSCTTY on stdin (the pty slave stdio the
            // launcher wired). arg=0: do not steal — the slave is
            // unowned (the supervisor never took it).
            if unsafe { libc::ioctl(0, libc::TIOCSCTTY as libc::Ioctl, 0i32) } != 0 {
                write_stderr("arapuca: supervisor: child TIOCSCTTY failed\n");
                unsafe { libc::_exit(1) };
            }
        }

        // Env surgery: strip the supervisor-only vars, add the
        // socketpair end. The wrapper sees a clean launcher-shaped
        // environment. In plain mode the pid-report var goes too
        // (the supervisor consumed the pipe); under ARAPUCA_PID_NS
        // the wrapper's relay is the writer and keeps it.
        let sp_env = format!("ARAPUCA_UNOTIFY_SP_FD={sp_child}");
        let envp: Vec<std::ffi::CString> = std::env::vars_os()
            .filter(|(k, _)| {
                (pidns_mode || k != "ARAPUCA_PID_REPORT_FD")
                    && k != "ARAPUCA_CGROUP_SYNC_FD"
                    && k != "ARAPUCA_SUPERVISOR"
            })
            .map(|(k, v)| {
                let kv = format!("{}={}", k.to_string_lossy(), v.to_string_lossy());
                std::ffi::CString::new(kv).unwrap_or_default()
            })
            .chain(std::iter::once(
                std::ffi::CString::new(sp_env).unwrap_or_default(),
            ))
            .collect();

        // argv: [arapuca, --, <cmd>...]
        let argv: Vec<std::ffi::CString> =
            std::iter::once(std::ffi::CString::new("arapuca").unwrap_or_default())
                .chain(std::iter::once(
                    std::ffi::CString::new("--").unwrap_or_default(),
                ))
                .chain(
                    args[cmd_start..]
                        .iter()
                        .map(|a| std::ffi::CString::new(a.as_str()).unwrap_or_default()),
                )
                .collect();

        let argv_ptrs: Vec<*const libc::c_char> = argv
            .iter()
            .map(|a| a.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp_ptrs: Vec<*const libc::c_char> = envp
            .iter()
            .map(|e| e.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let c_path = std::ffi::CString::new(wrapper_path).unwrap_or_default();

        // SAFETY: execve with valid argv/envp arrays; does not
        // return on success.
        unsafe {
            libc::execve(c_path.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
        }
        write_stderr(&format!(
            "arapuca: supervisor: exec wrapper: {}\n",
            std::io::Error::last_os_error()
        ));
        unsafe { libc::_exit(1) };
    }

    // ── Supervisor parent ────────────────────────────────────────
    // SAFETY: close the fork-child-side socketpair end.
    unsafe { libc::close(sp_child) };

    // The caller's extra_fds window ([3, 3+E)) is for the TARGET; the
    // fork child passes it through to the wrapper. Holding copies for
    // the supervisor's whole lifetime breaks close-to-signal
    // readiness patterns: a caller waiting for EOF on a passed pipe
    // never sees it while the target lives. The relay already closes
    // this range; the supervisor parent now does too. Nothing the
    // supervisor keeps lives in the window — its pipes and the
    // pinned fd all sit above it.
    {
        let target_fds = std::env::var("ARAPUCA_TARGET_FDS")
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(0);
        for fd in
            crate::wrapper::TARGET_FD_BASE..crate::wrapper::TARGET_FD_BASE + target_fds.clamp(0, 16)
        {
            // SAFETY: fd is an integer; EBADF from an already-closed
            // descriptor is ignored.
            unsafe { libc::close(fd) };
        }
    }

    // Fd hygiene (the plan's F4 closed-list): the supervisor is NOT
    // the writer of the wrapper-audit or DNS-audit pipes — the
    // wrapper is. Holding their write ends for the supervisor's
    // lifetime keeps the launcher's read side from EOF until the
    // target exits, so any audit-sink consumer's launch() blocks
    // for the target's whole lifetime (no kill(), no timeouts, no
    // stdin). The pinned wrapper fd is likewise child-only (the
    // exec of /proc/self/fd/N); the parent's copy is dead weight.
    // The unotify-audit fd is deliberately KEPT — the supervisor
    // is its writer.
    for var in ["ARAPUCA_AUDIT_FD", "ARAPUCA_DNS_AUDIT_FD"] {
        if let Some(fd) = std::env::var(var).ok().and_then(|s| s.parse::<i32>().ok()) {
            // SAFETY: fd inherited from the launcher; an EBADF from
            // an already-closed descriptor is ignored.
            unsafe { libc::close(fd) };
        }
    }
    // SAFETY: the parent's copy of the pinned wrapper fd; the fork
    // child kept its own for the execve.
    unsafe { libc::close(wrapper_fd) };

    // The pid report (plain mode): the supervisor is the writer.
    // Parent-branch only — see the comment above the fork.
    if let Some(fd) = pid_report_fd {
        if !pidns_mode {
            let bytes = child_pid.to_le_bytes();
            // SAFETY: write of 4 bytes on the launcher's pipe.
            let _ = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            // SAFETY: fd is a valid pipe end.
            unsafe { libc::close(fd) };
        }
    }

    // The wrapper is its own session and group leader (the fork child
    // setsid'd above); on tty runs it holds the controlling terminal,
    // so its group is the foreground group by construction. Nothing
    // to steer from this side — and steering it (setpgid/tcsetpgrp
    // from the supervisor's session) is exactly the shape that left
    // the target's group un-orphaned and wedgeable by SIGTSTP.

    // Apply the supervisor's own seccomp allowlist AFTER the fork
    // (filters inherit across fork and exec — applying it earlier
    // would kill the wrapper child). Failure is fail-closed: the
    // wrapper is still waiting for its ack and sees socketpair EOF.
    let seccomp_debug = std::env::var("ARAPUCA_SECCOMP_DEBUG").as_deref() == Ok("1");
    #[cfg(seccomp_supported)]
    if let Err(e) = apply_supervisor_seccomp(seccomp_debug) {
        write_stderr(&format!("arapuca: supervisor: seccomp: {e}\n"));
        unsafe { libc::_exit(1) };
    }

    // The config (strict parse — a malformed value never degrades
    // the policy).
    let config = match crate::env::parse_unotify_config() {
        Ok(Some(config)) => config,
        Ok(None) => {
            write_stderr("arapuca: supervisor: no unotify config\n");
            unsafe { libc::_exit(125) };
        }
        Err(e) => {
            write_stderr(&format!("arapuca: supervisor: {e}\n"));
            unsafe { libc::_exit(125) };
        }
    };
    let audit_fd: RawFd = std::env::var("ARAPUCA_UNOTIFY_AUDIT_FD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1);

    // O_NONBLOCK on the audit pipe — the legacy topology's defense,
    // dropped in the port: a target spamming intercepted syscalls
    // can fill the 64 KiB pipe, and a blocking write() here would
    // stall the supervisor (and with it every further intercepted
    // syscall in the target) forever. With O_NONBLOCK, events are
    // dropped and counted instead.
    if audit_fd >= 0 {
        // SAFETY: fcntl on a valid fd.
        let flags = unsafe { libc::fcntl(audit_fd, libc::F_GETFL) };
        if flags >= 0 {
            // SAFETY: fcntl on a valid fd.
            unsafe { libc::fcntl(audit_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        }
    }

    // The handover: read [host_pid, listener_fd], duplicate the
    // listener (parent → child: permitted by Yama without caps),
    // ack. The wrapper does not exec before the ack.
    let mut msg = [0u8; 8];
    if !read_exact_raw(sp_parent, &mut msg) {
        write_stderr("arapuca: supervisor: wrapper died before handover\n");
        reap_and_exit(child_pid, 125);
    }
    let wrapper_pid = i32::from_ne_bytes(msg[..4].try_into().unwrap());
    let remote_fd = i32::from_ne_bytes(msg[4..].try_into().unwrap());
    // SAFETY: pidfd_open on the wrapper (our descendant).
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, wrapper_pid, 0i32) } as i32;
    if pidfd < 0 {
        write_stderr("arapuca: supervisor: pidfd_open failed\n");
        reap_and_exit(child_pid, 125);
    }
    // SAFETY: pidfd_getfd of the listener from our descendant.
    let listener_fd =
        unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, remote_fd, 0u32) } as i32;
    // SAFETY: pidfd is a valid descriptor or -1 (closed either way).
    unsafe { libc::close(pidfd) };
    if listener_fd < 0 {
        write_stderr("arapuca: supervisor: pidfd_getfd failed\n");
        reap_and_exit(child_pid, 125);
    }
    // Ack: one byte back through the socketpair.
    // SAFETY: write of one byte on the socketpair parent end.
    unsafe {
        libc::write(sp_parent, [1u8].as_ptr().cast(), 1);
        libc::close(sp_parent);
    }

    // Serve notifications. The wrapper pid is watched so the loop
    // ends at wrapper death even when descendants carry the filter
    // (see supervisor_loop).
    let exit = supervisor_loop(listener_fd, audit_fd, &config, Some(child_pid));

    // Kill-or-wait: an abnormal loop exit while the wrapper may
    // still live must not stall (the wrapper's intercepted syscalls
    // would hang without a listener).
    if exit == LoopExit::Error {
        // SAFETY: tgkill on our own child.
        unsafe {
            libc::syscall(libc::SYS_tgkill, child_pid, child_pid, libc::SIGKILL);
        }
    }

    // Close the listener BEFORE the blocking wait: a notification
    // that arrives between the loop's exit and the wrapper's death
    // would otherwise block the target forever on a listener nobody
    // reads. With the fd closed, the kernel fails those intercepted
    // syscalls with ENOSYS — loudly, not silently wedged.
    // SAFETY: listener_fd is a valid descriptor or already closed
    // (close is idempotent enough here: EBADF is harmless).
    unsafe { libc::close(listener_fd) };

    // Reap and exit with the wrapper's status (exit code re-raised,
    // signal deaths re-raised — full fidelity, no status pipe).
    let mut wstatus: libc::c_int = 0;
    loop {
        // SAFETY: waitpid on our direct child.
        let ret = unsafe { libc::waitpid(child_pid, &mut wstatus, 0) };
        if ret == child_pid {
            if libc::WIFEXITED(wstatus) {
                unsafe { libc::_exit(libc::WEXITSTATUS(wstatus)) };
            }
            if libc::WIFSIGNALED(wstatus) {
                let sig = libc::WTERMSIG(wstatus);
                // SAFETY: signal + raise to die with the same signal.
                unsafe {
                    libc::signal(sig, libc::SIG_DFL);
                    libc::raise(sig);
                }
                unsafe { libc::_exit(128 + sig) };
            }
            unsafe { libc::_exit(125) };
        }
        if ret < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        unsafe { libc::_exit(125) };
    }
}

/// The wrapper pid for signal forwarding (set after the fork).
static WRAPPER_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Async-signal-safe handler: forward the signal to the wrapper.
/// tgkill over kill so the pid cannot be recycled mid-flight.
extern "C" fn supervisor_forward_signal(sig: libc::c_int) {
    let pid = WRAPPER_PID.load(std::sync::atomic::Ordering::Acquire);
    if pid > 0 {
        // SAFETY: tgkill on our own child.
        unsafe { libc::syscall(libc::SYS_tgkill, pid, pid, sig) };
    }
}

/// Reap the wrapper child and exit with `code` (failure paths where
/// the handover could not complete).
fn reap_and_exit(child_pid: i32, code: i32) -> ! {
    let mut wstatus: libc::c_int = 0;
    // SAFETY: waitpid on our direct child; the wrapper exits on its
    // own (ack EOF fail-closed) — bounded wait.
    let _ = unsafe { libc::waitpid(child_pid, &mut wstatus, 0) };
    unsafe { libc::_exit(code) };
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

    // I/O: /proc/<pid>/mem and /proc/<pid>/status reading, audit
    // pipe writing, socketpair recv, pidfd_open+pidfd_getfd for
    // listener FD transfer.
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
        libc::SYS_statx,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_wait4,
        // WNOWAIT exit check in supervisor_loop (does not reap —
        // the post-loop waitpid still owns the status).
        libc::SYS_waitid,
    ] {
        allow.insert(nr, vec![]);
    }

    // connect() broker (UDS connect policy): dial verified private
    // sockets, read the pinned fd's identity, and read the peer's
    // bound address.
    for nr in [
        libc::SYS_connect,
        libc::SYS_getsockopt,
        libc::SYS_getpeername,
    ] {
        allow.insert(nr, vec![]);
    }

    // socket: only the families the broker dials (AF_UNIX for the
    // policy itself, INET for emulated connects).
    let socket_rules = [libc::AF_UNIX, libc::AF_INET, libc::AF_INET6]
        .into_iter()
        .map(|family| {
            SeccompRule::new(vec![
                SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, family as u64)
                    .map_err(|e| Error::Seccomp(format!("socket condition: {e}")))?,
            ])
            .map_err(|e| Error::Seccomp(format!("socket rule: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    allow.insert(libc::SYS_socket, socket_rules);

    // clone: thread-creation flags only (helper threads completing
    // blocking emulated connects), namespace flags denied — same
    // rule shape as the bridge child.
    let clone_rule = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(crate::bridge::CLONE_THREAD_FLAGS),
            crate::bridge::CLONE_THREAD_FLAGS,
        )
        .map_err(|e| Error::Seccomp(format!("clone condition: {e}")))?,
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(crate::bridge::CLONE_NS_FLAGS),
            0,
        )
        .map_err(|e| Error::Seccomp(format!("clone ns deny condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("clone rule: {e}")))?;
    allow.insert(libc::SYS_clone, vec![clone_rule]);

    // ioctl: restrict to seccomp notification commands only.
    let allowed_ioctls: [u64; 5] = [
        SECCOMP_IOCTL_NOTIF_RECV as _,
        SECCOMP_IOCTL_NOTIF_SEND as _,
        SECCOMP_IOCTL_NOTIF_ADDFD as _,
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
        let syscalls = target_syscalls(true, false, false);
        assert!(syscalls.contains(&libc::SYS_openat));
        assert!(syscalls.contains(&437)); // openat2
        assert!(syscalls.contains(&libc::SYS_execve));
        assert!(syscalls.contains(&libc::SYS_execveat));
        assert!(!syscalls.contains(&libc::SYS_connect));
    }

    #[test]
    fn target_syscalls_network() {
        let syscalls = target_syscalls(false, true, false);
        assert!(syscalls.contains(&libc::SYS_connect));
        assert!(syscalls.contains(&libc::SYS_sendto));
        assert!(syscalls.contains(&libc::SYS_sendmsg));
        assert!(syscalls.contains(&libc::SYS_sendmmsg));
        assert!(!syscalls.contains(&libc::SYS_openat));
    }

    #[test]
    fn target_syscalls_both() {
        let syscalls = target_syscalls(true, true, false);
        assert!(syscalls.contains(&libc::SYS_openat));
        assert!(syscalls.contains(&libc::SYS_connect));
    }

    #[test]
    fn target_syscalls_neither() {
        let syscalls = target_syscalls(false, false, false);
        assert!(syscalls.is_empty());
    }

    #[test]
    fn target_syscalls_uds_policy() {
        // The connect broker intercepts connect() even without the
        // audit-network feature.
        let syscalls = target_syscalls(false, false, true);
        assert!(syscalls.contains(&libc::SYS_connect));
        assert!(!syscalls.contains(&libc::SYS_sendto));
        assert!(!syscalls.contains(&libc::SYS_openat));
        // With audit_network, no duplicates.
        let both = target_syscalls(false, true, true);
        assert_eq!(both.iter().filter(|&&n| n == libc::SYS_connect).count(), 1);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn target_syscalls_includes_open_on_x86_64() {
        let syscalls = target_syscalls(true, false, false);
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
                enforce_unix_connect: false,
                unix_deny_roots: Vec::new(),
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
                enforce_unix_connect: false,
                unix_deny_roots: Vec::new(),
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
                enforce_unix_connect: false,
                unix_deny_roots: Vec::new(),
            }
            .any_enabled()
        );
        assert!(
            UnotifyConfig {
                audit_file_access: false,
                audit_network: false,
                bridge_port: None,
                dns_port: None,
                enforce_network: false,
                enforce_unix_connect: true,
                unix_deny_roots: builtin_unix_deny_roots(),
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

    // ─── UDS connect policy: deny-root matching ──────────────────

    fn roots(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn deny_root_matches_exact_file() {
        let r = roots(&["/run/docker.sock"]);
        assert!(peer_denied("/run/docker.sock", &r));
        assert!(!peer_denied("/run/docker.sockx", &r));
    }

    #[test]
    fn deny_root_matches_beneath_directory() {
        let r = roots(&["/run/podman"]);
        assert!(peer_denied("/run/podman/podman.sock", &r));
        assert!(peer_denied("/run/podman", &r));
        assert!(
            !peer_denied("/run/podmanx/y.sock", &r),
            "component-wise only"
        );
    }

    #[test]
    fn deny_root_var_run_alias_normalized_both_directions() {
        // getpeername returns the listener's bind()-time literal, so
        // a daemon bound via the /var/run spelling reports it.
        let r = roots(&["/run/docker.sock"]);
        assert!(peer_denied("/var/run/docker.sock", &r));
        let r2 = roots(&["/var/run/libvirt"]);
        assert!(peer_denied("/run/libvirt/libvirt-sock", &r2));
        assert!(peer_denied("/var/run/libvirt/libvirt-sock", &r2));
    }

    #[test]
    fn deny_root_snap_docker_spelling() {
        let r = roots(&["/run/snap.docker.dockerd.sock"]);
        assert!(peer_denied("/run/snap.docker.dockerd.sock", &r));
        assert!(peer_denied("/var/run/snap.docker.dockerd.sock", &r));
    }

    #[test]
    fn deny_root_never_matches_user_runtime_dir() {
        // Rootless podman and friends live under /run/user/<uid>/.
        let r = roots(&["/run/podman", "/run/docker.sock"]);
        assert!(!peer_denied("/run/user/1000/podman/podman.sock", &r));
        assert!(!peer_denied("/var/run/user/1000/podman/podman.sock", &r));
    }

    #[test]
    fn deny_root_trailing_slash_tolerated() {
        let r = roots(&["/run/libvirt/"]);
        assert!(peer_denied("/run/libvirt/libvirt-sock", &r));
    }

    #[test]
    fn deny_root_dotdot_in_peer_literal_matched_literally() {
        // Only the daemon's bind string matters; a literal ".." in it
        // is matched as-is, not resolved.
        let r = roots(&["/run/x"]);
        assert!(!peer_denied("/run/../run/docker.sock", &r));
    }

    #[test]
    fn builtin_roots_cover_escape_daemons() {
        let r = builtin_unix_deny_roots();
        for peer in [
            "/run/docker.sock",
            "/var/run/docker.sock",
            "/run/snap.docker.dockerd.sock",
            "/run/podman/podman.sock",
            "/var/run/podman/podman.sock",
            "/run/containerd/containerd.sock",
            "/run/crio/crio.sock",
            "/run/dbus/system_bus_socket",
            "/var/run/dbus/system_bus_socket",
            "/run/libvirt/libvirt-sock",
            "/var/run/libvirt/libvirt-sock",
            "/run/systemd/private",
            "/run/lxd/unix.socket",
            "/var/lib/lxd/unix.socket",
            "/run/snapd.socket",
            "/run/snapd-snap.socket",
        ] {
            assert!(peer_denied(peer, &r), "builtin roots must deny {peer}");
        }
        // And must NOT deny the sanctioned rootless paths.
        assert!(!peer_denied("/run/user/1000/podman/podman.sock", &r));
    }

    // ─── UDS connect policy: BPF arch kill ───────────────────────

    #[test]
    fn bpf_kill_arch_appends_kill_return() {
        let bpf = build_unotify_bpf_kill_arch(&[libc::SYS_connect]).unwrap();
        // load arch + arch jump + load nr + pair(2) + ALLOW + KILL = 7
        assert_eq!(bpf.len(), 7);
        let last = bpf.last().unwrap();
        assert_eq!(last.code, BPF_RET | BPF_K);
        assert_eq!(last.k, libc::SECCOMP_RET_KILL_PROCESS);
        // The default (matching-arch, unmatched syscall) is still ALLOW.
        assert_eq!(bpf[bpf.len() - 2].k, 0x7fff_0000);
    }

    #[test]
    fn bpf_kill_arch_jump_skips_to_kill_instruction() {
        // With two syscalls the program is:
        // [load arch, jump, load nr, j1, notif, j2, notif, ALLOW, KILL]
        // The arch jump's false-branch must land on the KILL (last).
        let bpf = build_unotify_bpf_kill_arch(&[1, 2]).unwrap();
        let arch_jump = &bpf[1];
        let jf = arch_jump.jf as usize;
        // BPF jump offsets are relative to the next instruction
        // (index 2); the KILL is the last instruction.
        let target = 2 + jf;
        assert_eq!(target, bpf.len() - 1);
        assert_eq!(bpf[target].k, libc::SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn bpf_kill_arch_still_notifies_target_syscalls() {
        let bpf = build_unotify_bpf_kill_arch(&[libc::SYS_connect]).unwrap();
        assert!(
            bpf.iter()
                .any(|i| i.code == BPF_RET | BPF_K && i.k == libc::SECCOMP_RET_USER_NOTIF),
            "kill-arch BPF should still contain SECCOMP_RET_USER_NOTIF"
        );
    }

    #[test]
    fn wait_fd_ack_detects_ack_eof_and_timeout() {
        // Ack: the supervisor writes one byte then closes.
        let mut sv = [0i32; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    sv.as_mut_ptr(),
                )
            },
            0
        );
        // SAFETY: write one ack byte on the child end and close it.
        unsafe {
            libc::write(sv[1], [1u8].as_ptr().cast(), 1);
            libc::close(sv[1]);
        }
        assert!(wait_fd_ack(sv[0], 1000));
        // The ack arrives with the peer's close, so a readable
        // descriptor must win over the hangup.
        assert_eq!(
            wait_fd_ack_outcome(sv[0], 1000),
            AckOutcome::SupervisorGone,
            "the byte was already consumed by the call above"
        );
        // SAFETY: cleanup of the parent end.
        unsafe { libc::close(sv[0]) };

        // EOF: the supervisor closes without acking.
        let mut sv = [0i32; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    sv.as_mut_ptr(),
                )
            },
            0
        );
        // SAFETY: close the child end without writing.
        unsafe { libc::close(sv[1]) };
        assert!(!wait_fd_ack(sv[0], 1000));
        assert_eq!(
            wait_fd_ack_outcome(sv[0], 1000),
            AckOutcome::SupervisorGone,
            "EOF must not be reported as a timeout"
        );
        // SAFETY: cleanup of the parent end.
        unsafe { libc::close(sv[0]) };

        // Timeout: nothing arrives.
        let mut sv = [0i32; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    sv.as_mut_ptr(),
                )
            },
            0
        );
        let start = std::time::Instant::now();
        assert_eq!(wait_fd_ack_outcome(sv[0], 150), AckOutcome::TimedOut);
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(140),
            "the outcome variant must wait out the deadline"
        );
        assert!(!wait_fd_ack(sv[0], 150));
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(140),
            "timeout should elapse"
        );
        // SAFETY: cleanup of both ends.
        unsafe {
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
    }

    #[test]
    fn supervisor_seccomp_allows_broker_syscalls() {
        // Extends the write(2) smoke test to the connect-broker
        // surface: a filtered child must be able to create a socket
        // of an allowed family, getsockopt/getpeername it, and fcntl
        // it without being killed. clone-thread creation is covered
        // by an std::thread spawn inside the filtered child.
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
            // Socket of an allowed family.
            let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                unsafe { libc::_exit(3) };
            }
            // fd identity reads.
            if get_sockopt_int(fd, libc::SO_DOMAIN).unwrap_or(-1) != libc::AF_UNIX {
                unsafe { libc::_exit(4) };
            }
            if get_sockopt_int(fd, libc::SO_TYPE).unwrap_or(-1) != libc::SOCK_STREAM {
                unsafe { libc::_exit(5) };
            }
            // getpeername on an unconnected socket fails (ENOTCONN)
            // but must not kill the process.
            let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            let mut len: libc::socklen_t =
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
            unsafe {
                libc::getpeername(fd, &mut sa as *mut _ as *mut libc::sockaddr, &mut len);
            }
            // fcntl.
            if unsafe { libc::fcntl(fd, libc::F_GETFL) } < 0 {
                unsafe { libc::_exit(6) };
            }
            unsafe { libc::close(fd) };
            // Helper-thread creation (clone with thread flags).
            let ok = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = std::sync::Arc::clone(&ok);
            let handle = std::thread::Builder::new()
                .name("smoke".into())
                .spawn(move || {
                    flag.store(true, std::sync::atomic::Ordering::Relaxed);
                });
            if handle.is_err() {
                unsafe { libc::_exit(7) };
            }
            handle
                .expect("checked above")
                .join()
                .expect("helper must join");
            if !ok.load(std::sync::atomic::Ordering::Relaxed) {
                unsafe { libc::_exit(8) };
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
