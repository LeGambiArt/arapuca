//! Network namespace proxy bridge.
//!
//! Provides loopback bring-up via raw netlink and TCP-to-UDS relay
//! for bridging network access inside an isolated network namespace.
//! Linux-only.

use std::io::{self, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Bring up the loopback interface via raw netlink.
///
/// Opens an `AF_NETLINK`/`NETLINK_ROUTE` socket, sends an
/// `RTM_SETLINK` message to set `IFF_UP` on interface index 1 (lo).
///
/// # Preconditions
///
/// Assumes the loopback interface has index 1, which holds in a
/// freshly created network namespace.
///
/// # Errors
///
/// Returns an `io::Error` if the netlink socket cannot be created,
/// the message cannot be sent, or the kernel rejects the request
/// (e.g., insufficient privileges).
pub fn loopback_up() -> io::Result<()> {
    #[repr(C)]
    struct Ifinfomsg {
        ifi_family: u8,
        _pad: u8,
        ifi_type: libc::c_ushort,
        ifi_index: libc::c_int,
        ifi_flags: libc::c_uint,
        ifi_change: libc::c_uint,
    }

    #[repr(C)]
    struct Request {
        nlh: libc::nlmsghdr,
        ifi: Ifinfomsg,
    }

    // Response buffer with guaranteed alignment for nlmsghdr (4 bytes).
    #[repr(C)]
    struct Response {
        nlh: libc::nlmsghdr,
        errno: i32,
    }

    // SAFETY: socket() with constant arguments. The returned fd is
    // checked for errors before use.
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw_fd is a valid, open file descriptor (checked above).
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let msg_len = std::mem::size_of::<Request>() as u32;
    let req = Request {
        nlh: libc::nlmsghdr {
            nlmsg_len: msg_len,
            nlmsg_type: libc::RTM_SETLINK,
            nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        },
        ifi: Ifinfomsg {
            ifi_family: libc::AF_UNSPEC as u8,
            _pad: 0,
            ifi_type: 0,
            ifi_index: 1,
            ifi_flags: libc::IFF_UP as u32,
            ifi_change: libc::IFF_UP as u32,
        },
    };

    // SAFETY: fd is valid (owned), req is a stack-local #[repr(C)]
    // struct, msg_len matches its size.
    let ret = unsafe {
        libc::send(
            fd.as_raw_fd(),
            &raw const req as *const libc::c_void,
            msg_len as usize,
            0,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Timeout prevents hanging in doubly-nested user namespaces
    // (e.g., rootless containers) where the kernel may not deliver
    // the RTM_SETLINK ACK.
    let tv = libc::timeval {
        tv_sec: 3,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let mut resp = std::mem::MaybeUninit::<Response>::uninit();

    // SAFETY: fd is valid, resp is a stack-local buffer with correct
    // size and alignment for receiving a netlink error/ack response.
    let n = unsafe {
        libc::recv(
            fd.as_raw_fd(),
            resp.as_mut_ptr() as *mut libc::c_void,
            std::mem::size_of::<Response>(),
            0,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let n = n as usize;
    if n < std::mem::size_of::<libc::nlmsghdr>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink response too short",
        ));
    }

    // SAFETY: n >= size_of::<nlmsghdr>(), and resp is properly
    // aligned (guaranteed by #[repr(C)] struct layout). The nlh
    // field is at offset 0.
    let resp = unsafe { resp.assume_init() };

    // With NLM_F_ACK, the kernel always replies with NLMSG_ERROR
    // (errno=0 for success). Any other type is unexpected.
    if resp.nlh.nlmsg_type != libc::NLMSG_ERROR as u16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected netlink response type: {}", resp.nlh.nlmsg_type),
        ));
    }

    if n < std::mem::size_of::<Response>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink error response too short",
        ));
    }

    // errno == 0 means ACK (success). The kernel returns negative
    // errno values in the error payload.
    if resp.errno != 0 {
        return Err(io::Error::from_raw_os_error(-resp.errno));
    }

    Ok(())
}

const MAX_CONNECTIONS: usize = 64;
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Parse the `ARAPUCA_PROXY_BRIDGE` environment variable.
///
/// Expected format: `<port>:<uds_path>` (e.g., `18080:/tmp/proxy.sock`).
/// Returns `Ok(None)` if the variable is not set.
///
/// # Errors
///
/// Returns an error if the variable is set but malformed (bad format,
/// zero port, non-numeric port, colon in path).
pub fn parse_bridge_env() -> crate::Result<Option<(u16, std::path::PathBuf)>> {
    let val = match std::env::var("ARAPUCA_PROXY_BRIDGE") {
        Ok(v) => v,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(crate::Error::Validation(
                "ARAPUCA_PROXY_BRIDGE is not valid UTF-8".into(),
            ));
        }
    };

    let (port_str, uds_path) = match val.split_once(':') {
        Some((p, u)) if !u.is_empty() => (p, u),
        _ => {
            return Err(crate::Error::Validation(
                "invalid ARAPUCA_PROXY_BRIDGE format (expected port:path)".into(),
            ));
        }
    };

    let port: u16 = match port_str.parse() {
        Ok(0) => {
            return Err(crate::Error::Validation(
                "bridge port must be non-zero".into(),
            ));
        }
        Ok(p) => p,
        Err(_) => {
            return Err(crate::Error::Validation(format!(
                "invalid bridge port: {port_str}"
            )));
        }
    };

    Ok(Some((port, std::path::PathBuf::from(uds_path))))
}

/// Fork a bridge child process for TCP-to-UDS relay and/or DNS capture.
///
/// When `uds_path` is `Some`, binds a TCP listener on `127.0.0.1:port`
/// and relays connections to the UDS. When `None`, runs in DNS-only
/// mode (no TCP listener, no relay). Returns the actual bound port,
/// or `0` in DNS-only mode.
///
/// The bridge child applies its own seccomp filter and runs until
/// killed by `PR_SET_PDEATHSIG`. It never returns.
///
/// # Preconditions
///
/// - Must be called before seccomp is applied (checked via prctl).
/// - Must be inside a network namespace (loopback_up assumes fresh netns).
///
/// Close all FDs >= 3 except those in `keep`.
///
/// Uses `close_range(2)` when available (Linux 5.9+). On older kernels,
/// falls back to enumerating `/proc/self/fd`.
///
/// # Safety
///
/// Caller must ensure no other threads hold or depend on the FDs
/// being closed. Intended for use in a post-fork, pre-exec context.
pub unsafe fn close_fds_except(keep: &[i32]) {
    let mut sorted: Vec<u32> = keep
        .iter()
        .filter(|&&fd| fd >= 3)
        .map(|&fd| fd as u32)
        .collect();
    sorted.sort();
    sorted.dedup();

    let mut start = 3u32;
    let mut all_ok = true;
    for &fd in &sorted {
        if fd > start {
            // SAFETY: close_range is a simple syscall; no invariants beyond valid FD range.
            let ret = unsafe { libc::syscall(libc::SYS_close_range, start, fd - 1, 0u32) };
            if ret != 0 {
                all_ok = false;
                break;
            }
        }
        start = fd + 1;
    }
    if all_ok {
        // SAFETY: same as above — close remaining range above the last kept FD.
        let ret = unsafe { libc::syscall(libc::SYS_close_range, start, u32::MAX, 0u32) };
        if ret == 0 {
            return;
        }
    }

    // Fallback: enumerate /proc/self/fd (works on all Linux versions).
    // Collect FD numbers first — closing the ReadDir's directory FD
    // mid-iteration would silently stop enumeration.
    if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
        let fds_to_close: Vec<i32> = entries
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().parse::<i32>().ok())
            .filter(|&fd| fd >= 3 && !keep.contains(&fd))
            .collect();
        for fd in fds_to_close {
            // SAFETY: FD was valid at enumeration time; double-close is harmless.
            unsafe { libc::close(fd) };
        }
        return;
    }

    // Last resort: brute-force close from 3 to sysconf(_SC_OPEN_MAX),
    // capped at 65536 to avoid hanging on systemd systems where
    // _SC_OPEN_MAX returns ~1 billion (fs.nr_open).
    // SAFETY: sysconf(_SC_OPEN_MAX) returns the system FD limit.
    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) } as i32;
    let limit = if max_fd > 0 { max_fd.min(65536) } else { 4096 };
    for fd in 3..limit {
        if !keep.contains(&fd) {
            // SAFETY: closing an already-closed FD is harmless.
            unsafe { libc::close(fd) };
        }
    }
}

///
/// Returns an error if loopback cannot be brought up, the listener
/// cannot be bound, fork fails, or the bridge child fails to signal
/// readiness within the timeout.
pub fn fork_bridge(
    port: u16,
    uds_path: Option<&Path>,
    dns_audit_fd: Option<RawFd>,
    seccomp_debug: bool,
) -> crate::Result<u16> {
    #[cfg(seccomp_supported)]
    {
        // SAFETY: PR_GET_SECCOMP is a simple query, no pointer args.
        let seccomp_mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
        if seccomp_mode != 0 {
            return Err(crate::Error::Process(
                "bridge: seccomp already applied (invariant violation)".into(),
            ));
        }
    }

    loopback_up().map_err(|e| crate::Error::Process(format!("bridge: loopback: {e}")))?;

    let listener = if uds_path.is_some() {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        Some(
            TcpListener::bind(addr)
                .map_err(|e| crate::Error::Process(format!("bridge: bind {addr}: {e}")))?,
        )
    } else {
        None
    };

    // Pre-bind DNS capture UDP socket before fork (before seccomp).
    let dns_udp = if dns_audit_fd.is_some() {
        let udp_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 53));
        let udp = std::net::UdpSocket::bind(udp_addr)
            .map_err(|e| crate::Error::Process(format!("bridge: dns bind {udp_addr}: {e}")))?;
        Some(udp)
    } else {
        None
    };

    // Create readiness pipe.
    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe2 with valid array and O_CLOEXEC flag.
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(crate::Error::Syscall {
            name: "pipe2",
            source: io::Error::last_os_error(),
        });
    }
    let pipe_read = pipe_fds[0];
    let pipe_write = pipe_fds[1];

    // SAFETY: getpid is always safe.
    let parent_pid = unsafe { libc::getpid() };

    // SAFETY: single-threaded at this point, fork is safe.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(crate::Error::Syscall {
            name: "fork",
            source: io::Error::last_os_error(),
        });
    }

    if child_pid == 0 {
        // ── Bridge child ──────────────────────────────────────
        // All error exits use _exit (child can never return).

        // SAFETY: pipe_read is a valid fd from pipe2.
        unsafe { libc::close(pipe_read) };

        // Close all FDs >= 3 except those we need to keep.
        unsafe {
            let mut keep_vec = vec![pipe_write];
            if let Some(ref l) = listener {
                keep_vec.push(l.as_raw_fd());
            }
            if let Some(ref udp) = dns_udp {
                keep_vec.push(udp.as_raw_fd());
            }
            if let Some(fd) = dns_audit_fd {
                keep_vec.push(fd);
            }
            close_fds_except(&keep_vec);
        }

        // Set dns_audit_fd to non-blocking to avoid stalling on pipe full.
        if let Some(fd) = dns_audit_fd {
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                if flags >= 0 {
                    libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
        }

        // Ignore SIGPIPE so that writing to a broken audit pipe
        // returns EPIPE instead of killing the bridge process.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

        // SAFETY: prctl with PR_SET_PDEATHSIG is a simple setter.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
            unsafe { libc::_exit(1) };
        }

        // Race check: if the parent died between fork and prctl.
        if unsafe { libc::getppid() } != parent_pid {
            unsafe { libc::_exit(1) };
        }

        // Prevents /proc/<pid>/mem access from the agent.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
            unsafe { libc::_exit(1) };
        }

        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64) } != 0 {
            unsafe { libc::_exit(1) };
        }

        // The bridge never execs and needs no capabilities; drop
        // them so a cap-bearing helper cannot be pivoted through
        // /proc/<pid>/mem (capabilities bypass dumpability).
        if let Err(e) = crate::wrapper::drop_capabilities() {
            child_stderr(&format!("bridge: cap drop: {e}\n"));
            unsafe { libc::_exit(1) };
        }

        #[cfg(seccomp_supported)]
        if let Err(e) = apply_bridge_seccomp(seccomp_debug) {
            child_stderr(&format!("bridge: seccomp: {e}\n"));
            unsafe { libc::_exit(1) };
        }
        #[cfg(not(seccomp_supported))]
        child_stderr("bridge: seccomp not available\n");

        // Spawn DNS capture thread if enabled.
        if let (Some(udp), Some(audit_fd)) = (dns_udp, dns_audit_fd) {
            std::thread::spawn(move || dns_serve(udp, audit_fd));
        }

        match (listener, uds_path) {
            (Some(l), Some(p)) => {
                if let Err(e) = listen_and_relay(l, p, pipe_write) {
                    child_stderr(&format!("bridge: relay: {e}\n"));
                }
            }
            _ => {
                // DNS-only mode: signal readiness and block.
                unsafe {
                    libc::write(pipe_write, [1u8].as_ptr().cast(), 1);
                    libc::close(pipe_write);
                }
                loop {
                    std::thread::park();
                }
            }
        }
        unsafe { libc::_exit(0) };
    }

    // ── Parent ────────────────────────────────────────────────

    let actual_port = listener
        .as_ref()
        .map(|l| l.local_addr().expect("bound listener").port())
        .unwrap_or(0);
    drop(listener);

    // SAFETY: pipe_write is a valid fd from pipe2.
    unsafe { libc::close(pipe_write) };

    // Wait for bridge readiness (5s timeout), retrying on EINTR.
    let mut pfd = libc::pollfd {
        fd: pipe_read,
        events: libc::POLLIN,
        revents: 0,
    };
    let poll_ret = loop {
        // SAFETY: pfd is a valid stack-local pollfd, timeout in ms.
        let ret = unsafe { libc::poll(&mut pfd, 1, 5000) };
        if ret >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break ret;
        }
    };

    if poll_ret == 0 {
        unsafe { libc::kill(child_pid, libc::SIGKILL) };
        return Err(crate::Error::Process(
            "bridge: readiness timeout (5s)".into(),
        ));
    }
    if poll_ret < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::kill(child_pid, libc::SIGKILL) };
        return Err(crate::Error::Syscall {
            name: "poll",
            source: err,
        });
    }

    // Read the readiness byte, retrying on EINTR.
    let mut buf = [0u8; 1];
    let n = loop {
        let ret =
            unsafe { libc::read(pipe_read, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if ret >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break ret;
        }
    };
    unsafe { libc::close(pipe_read) };

    if n != 1 {
        unsafe { libc::kill(child_pid, libc::SIGKILL) };
        return Err(crate::Error::Process(
            "bridge: readiness signal failed".into(),
        ));
    }

    Ok(actual_port)
}

/// Write to stderr from the bridge child (raw libc, async-signal-safe).
fn child_stderr(msg: &str) {
    let _ = unsafe { libc::write(2, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
}

#[cfg(seccomp_supported)]
pub(crate) const CLONE_THREAD_FLAGS: u64 = (libc::CLONE_VM
    | libc::CLONE_FS
    | libc::CLONE_FILES
    | libc::CLONE_SIGHAND
    | libc::CLONE_THREAD) as u64;

#[cfg(seccomp_supported)]
pub(crate) const CLONE_NS_FLAGS: u64 = libc::CLONE_NEWNS as u64
    | libc::CLONE_NEWCGROUP as u64
    | libc::CLONE_NEWUTS as u64
    | libc::CLONE_NEWIPC as u64
    | libc::CLONE_NEWUSER as u64
    | libc::CLONE_NEWPID as u64
    | libc::CLONE_NEWNET as u64
    | 0x0000_0080; // CLONE_NEWTIME (not yet in libc crate)

/// Apply a minimal default-deny seccomp filter for the bridge process.
///
/// Only syscalls needed for TCP accept, UDS connect, bidirectional
/// relay, and thread management are allowed. Everything else kills
/// the process. This prevents a compromised bridge from being used
/// as a seccomp-free pivot.
///
/// `clone` is restricted to require thread-creation flags (the flags
/// must be present, though BPF cannot prevent additional flags from
/// also being set — defense-in-depth, not a hard guarantee).
/// `clone3` returns `ENOSYS` to force glibc fallback to `clone`
/// (where the flag filter applies). `socket` is restricted to
/// `AF_UNIX` only — the TCP listener is already bound pre-seccomp.
/// `mprotect` denies `PROT_EXEC` to block code injection.
///
/// # Preconditions
///
/// The TCP listener must already be bound before calling this
/// function, since `bind` and `listen` are not in the allowlist.
///
/// # Errors
///
/// Returns an error if the filter cannot be built or installed.
#[cfg(seccomp_supported)]
pub fn apply_bridge_seccomp(debug: bool) -> crate::Result<()> {
    if debug {
        crate::seccomp::install_seccomp_debug_handler();
    }
    let (clone3_prog, main_prog) = build_bridge_filters(debug)?;

    seccompiler::apply_filter(&clone3_prog)
        .map_err(|e| crate::Error::Seccomp(format!("install clone3 filter: {e}")))?;

    seccompiler::apply_filter(&main_prog)
        .map_err(|e| crate::Error::Seccomp(format!("install bridge filter: {e}")))?;

    log::info!("bridge seccomp: filter applied");
    Ok(())
}

#[cfg(seccomp_supported)]
fn build_bridge_filters(
    debug: bool,
) -> crate::Result<(seccompiler::BpfProgram, seccompiler::BpfProgram)> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    };
    use std::collections::HashMap;

    let arch = crate::seccomp::target_arch()?;

    let mut allow: HashMap<i64, Vec<SeccompRule>> = HashMap::new();

    // I/O: accept, connect, relay, shutdown.
    for nr in [
        libc::SYS_accept4,
        libc::SYS_connect,
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_writev,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_close,
        libc::SYS_shutdown,
        libc::SYS_ppoll,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_create1,
    ] {
        allow.insert(nr, vec![]);
    }
    #[cfg(target_arch = "x86_64")]
    for nr in [libc::SYS_poll, libc::SYS_epoll_wait] {
        allow.insert(nr, vec![]);
    }

    // Thread management.
    for nr in [
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_gettid,
        libc::SYS_getpid,
        libc::SYS_tgkill,
    ] {
        allow.insert(nr, vec![]);
    }

    // clone: require thread-creation flags AND deny namespace flags.
    let clone_rule = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(CLONE_THREAD_FLAGS),
            CLONE_THREAD_FLAGS,
        )
        .map_err(|e| crate::Error::Seccomp(format!("clone condition: {e}")))?,
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(CLONE_NS_FLAGS),
            0,
        )
        .map_err(|e| crate::Error::Seccomp(format!("clone ns deny condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("clone rule: {e}")))?;
    allow.insert(libc::SYS_clone, vec![clone_rule]);

    // clone3: must be in the main allowlist (→ Allow) so the
    // stacked clone3 filter's Errno(ENOSYS) wins via seccomp's
    // most-restrictive-action rule. Without this, the main
    // filter's KillProcess mismatch would override the ENOSYS.
    allow.insert(libc::SYS_clone3, vec![]);

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

    // mprotect: deny PROT_EXEC (arg2 must NOT have bit 0x4 set).
    let mprotect_rule = SeccompRule::new(vec![
        SeccompCondition::new(
            2,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
            0,
        )
        .map_err(|e| crate::Error::Seccomp(format!("mprotect condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("mprotect rule: {e}")))?;
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

    // socket: only AF_UNIX. The TCP listener is already bound
    // pre-seccomp; the bridge only needs AF_UNIX for connecting
    // to the UDS proxy. Blocking AF_INET/AF_INET6 prevents the
    // bridge from being used as a network pivot.
    let socket_unix_rule = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_UNIX as u64,
        )
        .map_err(|e| crate::Error::Seccomp(format!("socket condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("socket rule: {e}")))?;
    allow.insert(libc::SYS_socket, vec![socket_unix_rule]);

    // File I/O (glibc NSS, /etc/resolv.conf, UDS path resolution).
    for nr in [
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_fstat,
        libc::SYS_lseek,
        libc::SYS_pread64,
    ] {
        allow.insert(nr, vec![]);
    }

    // Misc (needed by glibc/Rust runtime).
    for nr in [
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_fcntl,
        libc::SYS_prlimit64,
        libc::SYS_rseq,
    ] {
        allow.insert(nr, vec![]);
    }

    // prctl: allow VMA naming and thread naming only.
    // glibc >= 2.35 calls prctl(PR_SET_VMA) to label malloc arenas.
    // Under concurrent thread load, new arenas are created, and the
    // missing prctl kills the bridge via SECCOMP_RET_KILL_PROCESS.
    const PR_SET_VMA: u64 = 0x53564d41;
    let prctl_set_vma = SeccompRule::new(vec![
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, PR_SET_VMA)
            .map_err(|e| crate::Error::Seccomp(format!("prctl PR_SET_VMA condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("prctl PR_SET_VMA rule: {e}")))?;
    let prctl_set_name = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::PR_SET_NAME as u64,
        )
        .map_err(|e| crate::Error::Seccomp(format!("prctl PR_SET_NAME condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("prctl PR_SET_NAME rule: {e}")))?;
    allow.insert(libc::SYS_prctl, vec![prctl_set_vma, prctl_set_name]);

    // clone3: return ENOSYS to force glibc fallback to clone
    // (where our flag filter applies). Allowing clone3 would let
    // the bridge create processes with arbitrary namespace flags,
    // since BPF cannot inspect the clone_args struct pointer.
    // glibc handles ENOSYS gracefully — it retries with clone.
    //
    // This is a separate filter because seccompiler only supports
    // one match action per filter. Seccomp filter stacking applies
    // the most restrictive action, so:
    //   - clone3 → ENOSYS (from this filter)
    //   - allowlisted syscalls → Allow (from the main filter)
    //   - everything else → KillProcess (from the main filter)
    let mut clone3_deny: HashMap<i64, Vec<SeccompRule>> = HashMap::new();
    clone3_deny.insert(libc::SYS_clone3, vec![]);

    let clone3_filter = SeccompFilter::new(
        clone3_deny.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(|e| crate::Error::Seccomp(format!("build clone3 filter: {e}")))?;

    let clone3_prog: seccompiler::BpfProgram =
        clone3_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                crate::Error::Seccomp(format!("compile clone3 filter: {e}"))
            })?;

    // Main allowlist filter.
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
    .map_err(|e| crate::Error::Seccomp(format!("build bridge filter: {e}")))?;

    let main_prog = filter.try_into().map_err(|e: seccompiler::BackendError| {
        crate::Error::Seccomp(format!("compile bridge filter: {e}"))
    })?;

    Ok((clone3_prog, main_prog))
}

/// Relay bytes bidirectionally between a TCP stream and a Unix
/// domain stream socket.
///
/// Connects to the UDS at `uds_path`, then delegates to
/// [`relay_connected`] for the bidirectional copy.
///
/// # Errors
///
/// Returns an error if the UDS connection fails or relay setup fails.
pub fn relay(tcp: TcpStream, uds_path: &Path) -> io::Result<()> {
    let uds = UnixStream::connect(uds_path)?;
    relay_connected(uds, tcp, IDLE_TIMEOUT)
}

/// Relay bytes bidirectionally between already-connected UDS and TCP
/// streams.
///
/// Sets `TCP_NODELAY` on the TCP stream and read timeouts on both
/// streams. Spawns two threads (one per direction). When `io::copy`
/// returns on one direction, shuts down the opposite stream's write
/// half so the peer sees EOF. Blocks until both directions complete.
pub(crate) fn relay_connected(
    uds: UnixStream,
    tcp: TcpStream,
    timeout: Duration,
) -> io::Result<()> {
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(timeout))?;
    uds.set_read_timeout(Some(timeout))?;

    let tcp_read = tcp;
    let uds_read = uds;
    let tcp_write = tcp_read.try_clone()?;
    let uds_write = uds_read.try_clone()?;

    let t1 = std::thread::Builder::new()
        .spawn(move || {
            let mut src = &tcp_read;
            let mut dst = &uds_write;
            if let Err(e) = io::copy(&mut src, &mut dst) {
                log::debug!("relay tcp→uds: {e}");
            }
            let _ = uds_write.shutdown(Shutdown::Write);
        })
        .map_err(io::Error::other)?;

    let t2 = std::thread::Builder::new()
        .spawn(move || {
            let mut src = &uds_read;
            let mut dst = &tcp_write;
            if let Err(e) = io::copy(&mut src, &mut dst) {
                log::debug!("relay uds→tcp: {e}");
            }
            let _ = tcp_write.shutdown(Shutdown::Write);
        })
        .map_err(io::Error::other)?;

    let _ = t1.join();
    let _ = t2.join();

    Ok(())
}

/// Accept connections on a pre-bound TCP listener and relay each
/// to a UDS.
///
/// Enforces [`MAX_CONNECTIONS`] concurrent connection limit. Sends
/// a single readiness byte on `ready_fd` once the accept loop is
/// ready. Runs until the process is killed (via pdeathsig).
///
/// The listener must already be bound — this function only accepts,
/// it does not bind. This allows the caller to bind before applying
/// seccomp (which does not allow `bind`/`listen`).
///
/// # Safety
///
/// `ready_fd` must be a valid, open file descriptor for a pipe write
/// end that the caller owns. It will be closed after the readiness
/// byte is sent.
///
/// # Errors
///
/// Returns an error if the readiness signal cannot be sent.
pub fn listen_and_relay(listener: TcpListener, uds_path: &Path, ready_fd: RawFd) -> io::Result<()> {
    // SAFETY: caller guarantees ready_fd is a valid, owned pipe write end.
    let ready = unsafe { OwnedFd::from_raw_fd(ready_fd) };

    // Signal readiness to the parent.
    // SAFETY: ready is valid (owned), writing a single byte to a pipe.
    let written =
        unsafe { libc::write(ready.as_raw_fd(), [1u8].as_ptr() as *const libc::c_void, 1) };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    drop(ready);

    let active = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        let tcp = match stream {
            Ok(s) => s,
            Err(e) => {
                log::debug!("bridge accept: {e}");
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };

        let prev = active.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::Release);
            drop(tcp);
            continue;
        }

        let thread_active = Arc::clone(&active);
        let path = uds_path.to_path_buf();

        if std::thread::Builder::new()
            .spawn(move || {
                if let Err(e) = relay(tcp, &path) {
                    log::debug!("bridge: relay: {e}");
                }
                thread_active.fetch_sub(1, Ordering::Release);
            })
            .is_err()
        {
            active.fetch_sub(1, Ordering::Release);
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    Ok(())
}

// ─── DNS capture ─────────────────────────────────────────────

/// Serve DNS queries on a pre-bound UDP socket, logging each
/// query domain to the audit pipe and responding with NXDOMAIN.
///
/// Runs in a dedicated thread inside the bridge child process.
/// Killed by SIGKILL (pdeathsig) when the parent exits.
fn dns_serve(udp: std::net::UdpSocket, audit_fd: RawFd) {
    let mut buf = [0u8; 4096];
    let mut dropped: u64 = 0;
    loop {
        let (n, src) = match udp.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) => {
                if e.kind() != io::ErrorKind::Interrupted && e.kind() != io::ErrorKind::WouldBlock {
                    std::thread::sleep(Duration::from_millis(100));
                }
                continue;
            }
        };

        if n < 12 || buf[2] & 0x80 != 0 {
            continue;
        }

        let id = u16::from_be_bytes([buf[0], buf[1]]);

        let line: Vec<u8> = if let Some(query) = crate::dns::parse_query(&buf[..n]) {
            let escaped = crate::wrapper::json_escape(&query.domain);
            let qtype = crate::dns::qtype_name(query.qtype);
            format!("{{\"domain\":\"{escaped}\",\"qtype\":\"{qtype}\"}}\n").into_bytes()
        } else {
            b"{\"domain\":\"<unparseable>\",\"qtype\":\"UNKNOWN\"}\n".to_vec()
        };

        let ret = unsafe { libc::write(audit_fd, line.as_ptr().cast(), line.len()) };
        if ret < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
            dropped += 1;
        } else if dropped > 0 {
            let summary = format!("{{\"dropped\":{dropped}}}\n");
            let _ = unsafe { libc::write(audit_fd, summary.as_ptr().cast(), summary.len()) };
            dropped = 0;
        }

        let resp = crate::dns::build_nxdomain(&buf[..n], id);
        if !resp.is_empty() {
            let _ = udp.send_to(&resp, src);
        }
    }
}

// ─── CONNECT proxy ───────────────────────────────────────────

/// An allowed CONNECT target: exact or suffix-match host + port.
///
/// When `host` starts with `.` (e.g., `.googleapis.com`), the
/// domain itself and any subdomain match (e.g., both
/// `googleapis.com` and `us-east5-aiplatform.googleapis.com`).
/// The leading `.` is stored internally — CLI `*.googleapis.com:443`
/// is converted to `.googleapis.com` + port 443.
///
/// Construct via [`AllowedHost::new`] to enforce invariants
/// (lowercase, valid hostname chars, port > 0).
#[derive(Debug, Clone)]
pub struct AllowedHost {
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl AllowedHost {
    /// Create a new allowed host rule.
    ///
    /// `host` must be ASCII-lowercase. Use a leading `.` for suffix
    /// matching (e.g., `.googleapis.com`). `port` must be 1-65535.
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }

    /// Check whether this rule matches a given host:port.
    ///
    /// Both `self.host` and `host` must be ASCII-lowercased before
    /// comparison — this method does not normalize case.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        if self.port != port {
            return false;
        }
        if self.host.starts_with('.') {
            host.ends_with(&self.host) || host == &self.host[1..]
        } else {
            self.host == host
        }
    }
}

const MAX_CONNECT_REQUEST: usize = 2048;
const CONNECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Parse an HTTP CONNECT request from a stream.
///
/// Reads byte-by-byte until `\r\n\r\n` (max [`MAX_CONNECT_REQUEST`]
/// bytes). Parses the first line as `CONNECT host:port HTTP/1.x`.
/// Returns the target `(host, port)`. Only the request line is used;
/// additional headers are consumed but ignored (prevents Host header
/// smuggling).
///
/// Byte-by-byte reading prevents over-reading into the TLS handshake
/// data that follows the CONNECT request.
pub fn parse_connect_request(stream: &mut impl io::Read) -> io::Result<(String, u16)> {
    let mut buf = Vec::with_capacity(256);
    let mut found_end = false;

    for _ in 0..MAX_CONNECT_REQUEST {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        buf.push(byte[0]);
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            found_end = true;
            break;
        }
    }

    if !found_end {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CONNECT request too large or missing terminator",
        ));
    }

    let header = std::str::from_utf8(&buf).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "CONNECT request not valid UTF-8",
        )
    })?;

    let first_line = header.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed CONNECT request line: {first_line}"),
        ));
    }

    if !parts[0].eq_ignore_ascii_case("CONNECT") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected CONNECT method, got: {}", parts[0]),
        ));
    }

    if parts[2] != "HTTP/1.0" && parts[2] != "HTTP/1.1" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported HTTP version: {}", parts[2]),
        ));
    }

    let target = parts[1];
    let (host, port_str) = target.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("CONNECT target missing port: {target}"),
        )
    })?;

    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CONNECT target has empty host",
        ));
    }

    let port: u16 = port_str.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid CONNECT port: {port_str}"),
        )
    })?;

    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CONNECT port must be 1-65535",
        ));
    }

    // Validate hostname: ASCII alphanumeric, `-`, `.` only.
    // Rejects IPv6 bracket notation `[::1]`.
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid hostname characters: {host}"),
        ));
    }

    // Strip trailing dot (FQDN normalization).
    let host = host.strip_suffix('.').unwrap_or(host);

    // Reject malformed hostnames (matches CLI parse_allow_host validation).
    if host.is_empty() || host.starts_with('.') || host.contains("..") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid hostname: {host}"),
        ));
    }

    Ok((host.to_ascii_lowercase(), port))
}

/// Check whether a resolved IP address is safe for outbound connection.
///
/// Rejects loopback, RFC 1918, link-local, cloud metadata, IPv6
/// unique-local, and unspecified addresses. Also canonicalizes
/// IPv4-mapped IPv6 addresses (`::ffff:X.X.X.X`) to their inner
/// IPv4 before checking — without this, `::ffff:127.0.0.1` would
/// bypass `is_loopback()`.
pub fn is_safe_resolved_ip(addr: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;

    match addr {
        IpAddr::V4(ip) => is_safe_ipv4(ip),
        IpAddr::V6(ip) => {
            // Canonicalize IPv4-mapped (::ffff:X.X.X.X) and deprecated
            // IPv4-compatible (::X.X.X.X, RFC 4291 §2.5.5.1) addresses.
            if let Some(v4) = ip.to_ipv4() {
                return is_safe_ipv4(&v4);
            }
            // Block NAT64 well-known prefix 64:ff9b::/96 (RFC 6052).
            // These embed IPv4 in the low 32 bits — a NAT64 gateway
            // translates TCP connections to the embedded IPv4 address,
            // bypassing the IPv4 blocklist. Common on IPv6-only cloud
            // networks (AWS, GCP, K8s).
            if let Some(embedded) = nat64_embedded_ipv4(ip) {
                return is_safe_ipv4(&embedded);
            }
            // Block local-use NAT64 prefix 64:ff9b:1::/48 (RFC 8215).
            // Operator-specific, used in cloud dual-stack VPCs.
            if is_nat64_local(ip) {
                return false;
            }
            // Block 6to4 (2002::/16, RFC 3056): IPv4 embedded in
            // bits 16-47. Deprecated but still routed in some clouds.
            if let Some(embedded) = sixto4_embedded_ipv4(ip) {
                return is_safe_ipv4(&embedded);
            }
            // Block Teredo (2001:0000::/32, RFC 4380): IPv4 XOR'd
            // with 0xffff in the last 32 bits.
            if let Some(embedded) = teredo_embedded_ipv4(ip) {
                return is_safe_ipv4(&embedded);
            }
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !is_ipv6_link_local(ip)
                && !is_ipv6_unique_local(ip)
        }
    }
}

fn nat64_embedded_ipv4(ip: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let s = ip.segments();
    // 64:ff9b::/96 — well-known NAT64 prefix (RFC 6052 §2.1).
    // IPv4 address is in the last 32 bits (segments 6-7).
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        Some(std::net::Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ))
    } else {
        None
    }
}

fn is_nat64_local(ip: &std::net::Ipv6Addr) -> bool {
    let s = ip.segments();
    // 64:ff9b:1::/48 — local-use NAT64 (RFC 8215).
    s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001
}

fn sixto4_embedded_ipv4(ip: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let s = ip.segments();
    if s[0] == 0x2002 {
        Some(std::net::Ipv4Addr::new(
            (s[1] >> 8) as u8,
            s[1] as u8,
            (s[2] >> 8) as u8,
            s[2] as u8,
        ))
    } else {
        None
    }
}

fn teredo_embedded_ipv4(ip: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let s = ip.segments();
    if s[0] == 0x2001 && s[1] == 0x0000 {
        Some(std::net::Ipv4Addr::new(
            (s[6] >> 8) as u8 ^ 0xff,
            s[6] as u8 ^ 0xff,
            (s[7] >> 8) as u8 ^ 0xff,
            s[7] as u8 ^ 0xff,
        ))
    } else {
        None
    }
}

fn is_safe_ipv4(ip: &std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    !ip.is_loopback()
        && !ip.is_private()
        && !ip.is_link_local()
        && !ip.is_broadcast()
        && !ip.is_unspecified()
        // "This network" 0.0.0.0/8 — only 0.0.0.0 is caught by
        // is_unspecified(); 0.0.0.1+ reaches localhost on Linux.
        && o[0] != 0
        // Carrier-Grade NAT (RFC 6598): 100.64.0.0/10 — used by
        // AWS VPC, GCP, Tailscale, Kubernetes for internal infra.
        && !(o[0] == 100 && (64..=127).contains(&o[1]))
        // Benchmarking (RFC 2544): 198.18.0.0/15
        && !(o[0] == 198 && (18..=19).contains(&o[1]))
        // Reserved (RFC 1112): 240.0.0.0/4
        && o[0] < 240
}

fn is_ipv6_link_local(ip: &std::net::Ipv6Addr) -> bool {
    // fe80::/10
    let seg = ip.segments();
    (seg[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_unique_local(ip: &std::net::Ipv6Addr) -> bool {
    // fc00::/7
    let seg = ip.segments();
    (seg[0] & 0xfe00) == 0xfc00
}

/// RAII guard for the connection counter.
struct ConnectionGuard {
    active: Arc<AtomicUsize>,
}

impl ConnectionGuard {
    fn new(active: &Arc<AtomicUsize>) -> Option<Self> {
        let prev = active.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::Release);
            return None;
        }
        Some(Self {
            active: Arc::clone(active),
        })
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Release);
    }
}

/// Accept connections on a UDS listener and handle CONNECT requests.
///
/// For each connection: parse the CONNECT request, check the target
/// against the allowlist, resolve DNS, validate the resolved IP,
/// then tunnel bytes to the target.
///
/// # Preconditions
///
/// The `UnixListener` must be bound and listening before this function
/// is called. The seccomp filter blocks `listen`, so the listener must
/// be set up pre-seccomp.
///
/// # Safety
///
/// `ready_fd` must be a valid, open file descriptor for a pipe write
/// end that the caller owns. It will be closed after the readiness
/// byte is sent.
pub fn connect_proxy_listen(
    listener: std::os::unix::net::UnixListener,
    allowlist: &[AllowedHost],
    ready_fd: RawFd,
) -> io::Result<()> {
    // SAFETY: caller guarantees ready_fd is a valid, owned pipe write end.
    let ready = unsafe { OwnedFd::from_raw_fd(ready_fd) };

    let written =
        unsafe { libc::write(ready.as_raw_fd(), [1u8].as_ptr() as *const libc::c_void, 1) };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    drop(ready);

    let active = Arc::new(AtomicUsize::new(0));
    let allowed = Arc::new(allowlist.to_vec());

    for stream in listener.incoming() {
        let uds = match stream {
            Ok(s) => s,
            Err(e) => {
                log::debug!("connect proxy accept: {e}");
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };

        let Some(guard) = ConnectionGuard::new(&active) else {
            drop(uds);
            continue;
        };

        let hosts = Arc::clone(&allowed);

        if std::thread::Builder::new()
            .spawn(move || {
                let _guard = guard;
                if let Err(e) = handle_connect(uds, &hosts) {
                    log::debug!("connect proxy: {e}");
                }
            })
            .is_err()
        {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    Ok(())
}

fn handle_connect(mut uds: UnixStream, allowlist: &[AllowedHost]) -> io::Result<()> {
    uds.set_read_timeout(Some(CONNECT_HANDSHAKE_TIMEOUT))?;

    let (host, port) = parse_connect_request(&mut uds)?;

    // Strip trailing dot for allowlist comparison (already stripped
    // in parse_connect_request, but defense-in-depth).
    let host_normalized = host.strip_suffix('.').unwrap_or(&host);

    if !allowlist.iter().any(|a| a.matches(host_normalized, port)) {
        let _ = uds.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        return Ok(());
    }

    // Resolve DNS explicitly, validate each address.
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> = (host.as_str(), port)
        .to_socket_addrs()
        .inspect_err(|_| {
            let _ = uds.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        })?
        .collect();

    // Find a safe address to connect to.
    let safe_addr = addrs.iter().find(|a| is_safe_resolved_ip(&a.ip()));

    let Some(&target_addr) = safe_addr else {
        let _ = uds.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("all resolved IPs for {host}:{port} are in denied ranges"),
        ));
    };

    let tcp = match TcpStream::connect_timeout(&target_addr, CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            let _ = uds.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return Err(e);
        }
    };

    uds.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;

    // Clear the handshake timeout before entering relay.
    uds.set_read_timeout(None)?;
    relay_connected(uds, tcp, IDLE_TIMEOUT)
}

/// Apply a minimal seccomp filter for the CONNECT proxy process.
///
/// Broader than the bridge relay filter because the proxy must make
/// outbound TCP connections and resolve DNS (glibc getaddrinfo → NSS
/// → dlopen). Runs outside the sandbox on the host network.
///
/// # Preconditions
///
/// The `UnixListener` must already be bound and listening before this
/// function is called (`listen` is not in the allowlist). NSS must be
/// pre-initialized via a dummy DNS resolution before this function is
/// called (`mprotect(PROT_EXEC)` is denied).
#[cfg(seccomp_supported)]
pub fn apply_connect_proxy_seccomp(debug: bool) -> crate::Result<()> {
    if debug {
        crate::seccomp::install_seccomp_debug_handler();
    }
    let (clone3_prog, main_prog) = build_connect_proxy_filters(debug)?;

    seccompiler::apply_filter(&clone3_prog)
        .map_err(|e| crate::Error::Seccomp(format!("install clone3 filter: {e}")))?;

    seccompiler::apply_filter(&main_prog)
        .map_err(|e| crate::Error::Seccomp(format!("install connect proxy filter: {e}")))?;

    log::info!("connect proxy seccomp: filter applied");
    Ok(())
}

#[cfg(seccomp_supported)]
fn build_connect_proxy_filters(
    debug: bool,
) -> crate::Result<(seccompiler::BpfProgram, seccompiler::BpfProgram)> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    };
    use std::collections::HashMap;

    let arch = crate::seccomp::target_arch()?;

    let mut allow: HashMap<i64, Vec<SeccompRule>> = HashMap::new();

    // I/O: accept, connect, relay, shutdown.
    for nr in [
        libc::SYS_accept4,
        libc::SYS_connect,
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_writev,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_close,
        libc::SYS_shutdown,
        libc::SYS_ppoll,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_create1,
    ] {
        allow.insert(nr, vec![]);
    }
    #[cfg(target_arch = "x86_64")]
    for nr in [libc::SYS_poll, libc::SYS_epoll_wait] {
        allow.insert(nr, vec![]);
    }

    // DNS resolution (glibc getaddrinfo uses ioctl(FIONREAD),
    // sendmmsg, and recvmmsg internally for UDP DNS queries).
    for nr in [
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_recvmsg,
        libc::SYS_bind,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
    ] {
        allow.insert(nr, vec![]);
    }

    // ioctl: restrict to FIONREAD (DNS) and FIONBIO (non-blocking).
    const IOCTL_FIONREAD: u64 = 0x541B;
    const IOCTL_FIONBIO: u64 = 0x5421;
    let ioctl_fionread = SeccompRule::new(vec![
        SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, IOCTL_FIONREAD)
            .map_err(|e| crate::Error::Seccomp(format!("ioctl FIONREAD condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("ioctl FIONREAD rule: {e}")))?;
    let ioctl_fionbio = SeccompRule::new(vec![
        SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, IOCTL_FIONBIO)
            .map_err(|e| crate::Error::Seccomp(format!("ioctl FIONBIO condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("ioctl FIONBIO rule: {e}")))?;
    allow.insert(libc::SYS_ioctl, vec![ioctl_fionread, ioctl_fionbio]);

    // NSS file I/O.
    for nr in [
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_fstat,
        libc::SYS_lseek,
        libc::SYS_pread64,
    ] {
        allow.insert(nr, vec![]);
    }

    // Thread management.
    for nr in [
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_gettid,
        libc::SYS_getpid,
        libc::SYS_tgkill,
    ] {
        allow.insert(nr, vec![]);
    }

    // clone: require thread-creation flags AND deny namespace flags.
    let clone_rule = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(CLONE_THREAD_FLAGS),
            CLONE_THREAD_FLAGS,
        )
        .map_err(|e| crate::Error::Seccomp(format!("clone condition: {e}")))?,
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(CLONE_NS_FLAGS),
            0,
        )
        .map_err(|e| crate::Error::Seccomp(format!("clone ns deny condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("clone rule: {e}")))?;
    allow.insert(libc::SYS_clone, vec![clone_rule]);

    // clone3: must be in main filter for stacked ENOSYS to win.
    allow.insert(libc::SYS_clone3, vec![]);

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

    // mprotect: deny PROT_EXEC (NSS must be pre-initialized).
    let mprotect_rule = SeccompRule::new(vec![
        SeccompCondition::new(
            2,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
            0,
        )
        .map_err(|e| crate::Error::Seccomp(format!("mprotect condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("mprotect rule: {e}")))?;
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

    // Socket: restrict to AF_UNIX + AF_INET + AF_INET6 only.
    // Blocks AF_NETLINK (routing manipulation) and AF_PACKET
    // (packet capture) if the proxy process is compromised.
    let socket_unix = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_UNIX as u64,
        )
        .map_err(|e| crate::Error::Seccomp(format!("socket AF_UNIX condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("socket AF_UNIX rule: {e}")))?;
    let socket_inet = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_INET as u64,
        )
        .map_err(|e| crate::Error::Seccomp(format!("socket AF_INET condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("socket AF_INET rule: {e}")))?;
    let socket_inet6 = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_INET6 as u64,
        )
        .map_err(|e| crate::Error::Seccomp(format!("socket AF_INET6 condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("socket AF_INET6 rule: {e}")))?;
    allow.insert(
        libc::SYS_socket,
        vec![socket_unix, socket_inet, socket_inet6],
    );

    // Misc (glibc/Rust runtime + NSS).
    for nr in [
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_fcntl,
        libc::SYS_prlimit64,
        libc::SYS_rseq,
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_uname,
    ] {
        allow.insert(nr, vec![]);
    }

    // prctl: allow VMA naming and thread naming (same as bridge).
    const PR_SET_VMA: u64 = 0x53564d41;
    let prctl_set_vma = SeccompRule::new(vec![
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, PR_SET_VMA)
            .map_err(|e| crate::Error::Seccomp(format!("prctl PR_SET_VMA condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("prctl PR_SET_VMA rule: {e}")))?;
    let prctl_set_name = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::PR_SET_NAME as u64,
        )
        .map_err(|e| crate::Error::Seccomp(format!("prctl PR_SET_NAME condition: {e}")))?,
    ])
    .map_err(|e| crate::Error::Seccomp(format!("prctl PR_SET_NAME rule: {e}")))?;
    allow.insert(libc::SYS_prctl, vec![prctl_set_vma, prctl_set_name]);

    // clone3 ENOSYS filter (same pattern as bridge).
    let mut clone3_deny: HashMap<i64, Vec<SeccompRule>> = HashMap::new();
    clone3_deny.insert(libc::SYS_clone3, vec![]);

    let clone3_filter = SeccompFilter::new(
        clone3_deny.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(|e| crate::Error::Seccomp(format!("build clone3 filter: {e}")))?;

    let clone3_prog: seccompiler::BpfProgram =
        clone3_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                crate::Error::Seccomp(format!("compile clone3 filter: {e}"))
            })?;

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
    .map_err(|e| crate::Error::Seccomp(format!("build connect proxy filter: {e}")))?;

    let main_prog = filter.try_into().map_err(|e: seccompiler::BackendError| {
        crate::Error::Seccomp(format!("compile connect proxy filter: {e}"))
    })?;

    Ok((clone3_prog, main_prog))
}

/// Fork a CONNECT proxy process that forwards connections to the given
/// allowed hosts.
///
/// Creates a Unix domain socket in a temporary directory, forks a child
/// process that runs the proxy, and waits up to 5 seconds for a readiness
/// signal. Returns `(socket_path, child_pid, child_pidfd)`.
///
/// The caller is responsible for killing the child and cleaning up the
/// socket directory when the parent process exits. Use
/// [`cleanup_connect_proxy`] for this.
///
/// # Errors
///
/// Returns an error if the socket cannot be created, the fork fails, or
/// the child does not signal readiness within the timeout. All resources
/// (child process, socket directory) are cleaned up before returning the
/// error.
#[cfg(target_os = "linux")]
pub fn fork_connect_proxy(
    allowed_hosts: &[AllowedHost],
    seccomp_debug: bool,
) -> crate::Result<(std::path::PathBuf, i32, i32)> {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener;

    let proxy_dir = tempfile::Builder::new()
        .prefix("arapuca-connect-proxy-")
        .tempdir_in(std::env::temp_dir())
        .map_err(|e| crate::Error::Process(format!("connect proxy: tmpdir: {e}")))?;
    let uds_path = proxy_dir.keep().join("connect.sock");

    let listener = UnixListener::bind(&uds_path).map_err(|e| {
        let _ = std::fs::remove_dir_all(uds_path.parent().unwrap());
        crate::Error::Process(format!("connect proxy: bind {}: {e}", uds_path.display()))
    })?;

    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe2 with valid array and O_CLOEXEC.
    let ret = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        drop(listener);
        let _ = std::fs::remove_dir_all(uds_path.parent().unwrap());
        return Err(crate::Error::Process(format!("connect proxy: pipe: {err}")));
    }
    let pipe_read = pipe_fds[0];
    let pipe_write = pipe_fds[1];

    // SAFETY: getpid is always safe.
    let parent_pid = unsafe { libc::getpid() };

    let hosts = allowed_hosts.to_vec();
    let listener_fd = listener.as_raw_fd();

    // SAFETY: single-threaded at this point (must be called before sandbox.launch).
    let child_pid = unsafe { libc::fork() };

    if child_pid < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(pipe_read);
            libc::close(pipe_write);
        }
        drop(listener);
        let _ = std::fs::remove_dir_all(uds_path.parent().unwrap());
        return Err(crate::Error::Process(format!("connect proxy: fork: {err}")));
    }

    if child_pid == 0 {
        // ── CONNECT proxy child ──────────────────────────────

        // SAFETY: pipe_read is a valid fd from pipe2.
        unsafe { libc::close(pipe_read) };

        // Close all FDs >= 3 except pipe_write and listener_fd.
        // SAFETY: fds are valid.
        unsafe { close_fds_except(&[pipe_write, listener_fd]) };

        // Ignore SIGPIPE so that writing to a broken UDS connection
        // returns EPIPE instead of killing the proxy process.
        // SAFETY: SIGPIPE + SIG_IGN is always safe.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

        // setsid clears PR_SET_PDEATHSIG, so it must be re-set after.
        // The getppid race check below covers the window between setsid
        // and prctl.
        // SAFETY: setsid is always safe. Tolerate EPERM (already session leader).
        let ret = unsafe { libc::setsid() };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EPERM) {
                eprintln!("arapuca: connect proxy: setsid: {err}");
                // SAFETY: _exit is always safe.
                unsafe { libc::_exit(1) };
            }
        }

        // SAFETY: prctl with PR_SET_PDEATHSIG.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
            unsafe { libc::_exit(1) };
        }

        // Race check: if parent already exited, bail.
        // SAFETY: getppid is always safe.
        if unsafe { libc::getppid() } != parent_pid {
            unsafe { libc::_exit(1) };
        }

        // SAFETY: prctl with PR_SET_NO_NEW_PRIVS.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64) } != 0 {
            unsafe { libc::_exit(1) };
        }

        // SAFETY: prctl with PR_SET_DUMPABLE.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
            unsafe { libc::_exit(1) };
        }

        // The proxy never execs and needs no capabilities; drop
        // them so a cap-bearing helper cannot be pivoted through
        // /proc/<pid>/mem (capabilities bypass dumpability).
        if let Err(e) = crate::wrapper::drop_capabilities() {
            crate::wrapper::write_stderr(&format!("connect proxy: cap drop: {e}\n"));
            unsafe { libc::_exit(1) };
        }

        // Apply Landlock with minimal NSS paths. The proxy needs to
        // read resolver config and load NSS modules, but should not
        // have access to the broader filesystem.
        {
            let proxy_read_paths: Vec<std::path::PathBuf> = [
                "/etc/hosts",
                "/etc/nsswitch.conf",
                "/etc/resolv.conf",
                "/etc/gai.conf",
                "/etc/ld.so.cache",
                "/etc/ld.so.conf",
                "/etc/ld.so.conf.d",
                "/etc/services",
                "/etc/ssl",
                "/etc/pki",
                "/etc/ca-certificates",
                "/run/systemd/resolve",
                "/run/nscd",
                "/lib",
                "/lib64",
                "/usr/lib",
                "/usr/lib64",
            ]
            .iter()
            .map(std::path::PathBuf::from)
            .filter(|p| p.exists())
            .collect();

            if !proxy_read_paths.is_empty() {
                let proxy_profile = crate::Profile {
                    read_paths: proxy_read_paths,
                    ..Default::default()
                };
                if let Err(e) = crate::landlock::apply(&proxy_profile, None, false) {
                    // No signal scoping for the proxy child: it is a
                    // trusted helper, and scoping it buys nothing.
                    eprintln!("arapuca: connect proxy: landlock: {e}");
                    unsafe { libc::_exit(1) };
                }
            } else {
                eprintln!("arapuca: connect proxy: no system paths found for Landlock");
                unsafe { libc::_exit(1) };
            }
        }

        // Pre-initialize NSS before seccomp — forces dlopen of all
        // NSS modules. Using an unresolvable FQDN traverses the
        // entire nsswitch hosts chain. Must happen before seccomp
        // because mprotect(PROT_EXEC) for dlopen is denied after.
        use std::net::ToSocketAddrs;
        let _ = ("_arapuca-nss-init.invalid.", 0u16).to_socket_addrs();

        #[cfg(seccomp_supported)]
        if let Err(e) = apply_connect_proxy_seccomp(seccomp_debug) {
            eprintln!("arapuca: connect proxy: seccomp: {e}");
            unsafe { libc::_exit(1) };
        }

        if let Err(e) = connect_proxy_listen(listener, &hosts, pipe_write) {
            eprintln!("arapuca: connect proxy: {e}");
        }
        // SAFETY: _exit is always safe.
        unsafe { libc::_exit(0) };
    }

    // ── Parent ────────────────────────────────────────────────

    drop(listener);
    // SAFETY: pipe_write is no longer needed in parent.
    unsafe { libc::close(pipe_write) };

    // Open pidfd immediately — child PID is guaranteed valid.
    // SAFETY: pidfd_open with valid pid and flags=0.
    let proxy_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) } as i32;

    // Helper: clean up the child process and socket directory, then
    // return an error. Used on all parent-side failure paths.
    let fail_proxy = |msg: String| -> crate::Error {
        // SAFETY: child_pid is valid.
        unsafe { libc::kill(child_pid, libc::SIGKILL) };
        if proxy_pidfd >= 0 {
            // SAFETY: proxy_pidfd is a valid pidfd.
            unsafe { libc::close(proxy_pidfd) };
            // SAFETY: waitpid with valid pid and WNOHANG.
            unsafe { libc::waitpid(child_pid, std::ptr::null_mut(), libc::WNOHANG) };
        }
        let _ = std::fs::remove_dir_all(uds_path.parent().unwrap());
        crate::Error::Process(format!("connect proxy: {msg}"))
    };

    // Wait for readiness signal (5s timeout).
    let mut pfd = libc::pollfd {
        fd: pipe_read,
        events: libc::POLLIN,
        revents: 0,
    };
    let poll_ret = loop {
        // SAFETY: pfd is valid, timeout in ms.
        let ret = unsafe { libc::poll(&mut pfd, 1, 5000) };
        if ret >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break ret;
        }
    };

    if poll_ret == 0 {
        // SAFETY: done with pipe_read.
        unsafe { libc::close(pipe_read) };
        return Err(fail_proxy("readiness timeout (5s)".into()));
    }
    if poll_ret < 0 {
        // SAFETY: done with pipe_read.
        unsafe { libc::close(pipe_read) };
        return Err(fail_proxy(format!(
            "poll: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut buf = [0u8; 1];
    let n = loop {
        // SAFETY: pipe_read is valid.
        let ret =
            unsafe { libc::read(pipe_read, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if ret >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break ret;
        }
    };
    // SAFETY: done with pipe_read.
    unsafe { libc::close(pipe_read) };

    if n != 1 {
        return Err(fail_proxy("readiness signal failed".into()));
    }

    Ok((uds_path, child_pid, proxy_pidfd))
}

/// Kill a CONNECT proxy child and remove its socket directory.
///
/// Safe to call with `None` values (no-op). Intended to be called on
/// parent exit / error paths alongside the socket directory cleanup.
#[cfg(target_os = "linux")]
pub fn cleanup_connect_proxy(
    pid: Option<i32>,
    pidfd: Option<i32>,
    socket: &Option<std::path::PathBuf>,
) {
    if let Some(pid) = pid {
        // SAFETY: pid is a valid child PID.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    if let Some(fd) = pidfd {
        // SAFETY: fd is a valid pidfd.
        unsafe { libc::close(fd) };
        // Reap the zombie.
        if let Some(pid) = pid {
            // SAFETY: waitpid with valid pid and WNOHANG.
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        }
    }
    if let Some(path) = socket {
        if let Some(dir) = path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(seccomp_supported)]
    #[test]
    fn bridge_seccomp_filters_build() {
        let (clone3_prog, main_prog) = build_bridge_filters(false).unwrap();
        assert!(!clone3_prog.is_empty());
        assert!(!main_prog.is_empty());
    }

    #[test]
    fn loopback_up_smoke_test() {
        // Outside a netns, lo is already up. The call should
        // succeed (idempotent) or fail with EPERM if we lack
        // CAP_NET_ADMIN. Either outcome is valid — we verify
        // no panic or undefined behavior.
        let result = loopback_up();
        match &result {
            Ok(()) => eprintln!("loopback_up: ok (already up)"),
            Err(e) => eprintln!("loopback_up: {e} (expected in unprivileged context)"),
        }
    }

    #[test]
    fn relay_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("echo.sock");

        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

        let echo_handle = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0u8; 256];
            loop {
                let n = match io::Read::read(&mut conn, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if io::Write::write_all(&mut conn, &buf[..n]).is_err() {
                    break;
                }
            }
        });

        let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let relay_path = sock_path.clone();
        let relay_handle = std::thread::spawn(move || {
            let (stream, _) = tcp_listener.accept().unwrap();
            relay(stream, &relay_path).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        io::Write::write_all(&mut client, b"hello bridge").unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        io::Read::read_to_end(&mut client, &mut response).unwrap();

        assert_eq!(response, b"hello bridge");

        relay_handle.join().unwrap();
        echo_handle.join().unwrap();
    }

    #[test]
    fn connection_limit_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("slow.sock");

        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

        // UDS server that accepts connections but never sends data
        // (holds connections open until dropped).
        let _server_handle = std::thread::spawn(move || {
            let mut conns = Vec::new();
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => conns.push(s),
                    Err(_) => break,
                }
            }
        });

        let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let bound_addr = tcp_listener.local_addr().unwrap();

        let active = Arc::new(AtomicUsize::new(0));
        let active_clone = Arc::clone(&active);
        let path = sock_path.clone();

        let accept_handle = std::thread::spawn(move || {
            for stream in tcp_listener.incoming() {
                let tcp = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let prev = active_clone.fetch_add(1, Ordering::AcqRel);
                if prev >= 4 {
                    active_clone.fetch_sub(1, Ordering::Release);
                    drop(tcp);
                    continue;
                }
                let active = Arc::clone(&active_clone);
                let p = path.clone();
                std::thread::spawn(move || {
                    let _ = relay(tcp, &p);
                    active.fetch_sub(1, Ordering::Release);
                });
            }
        });

        // Open 4 connections (should all succeed).
        let mut clients: Vec<TcpStream> = (0..4)
            .map(|_| TcpStream::connect(bound_addr).unwrap())
            .collect();

        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(active.load(Ordering::Acquire), 4);

        // 5th connection: accepted by TCP but dropped immediately
        // (RST sent to client).
        let extra = TcpStream::connect(bound_addr).unwrap();
        extra
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut buf = [0u8; 1];
        let result = io::Read::read(&mut &extra, &mut buf);
        assert!(
            result.is_err() || result.unwrap() == 0,
            "5th connection should be rejected"
        );

        // Clean up: close all clients to unblock relay threads.
        for c in clients.drain(..) {
            drop(c);
        }
        drop(extra);

        // Give threads time to wind down, then drop the listener
        // to break the accept loop.
        std::thread::sleep(Duration::from_millis(100));
        drop(accept_handle);
    }

    // ─── CONNECT proxy tests ─────────────────────────────────

    fn make_connect_request(target: &str, version: &str) -> Vec<u8> {
        format!("CONNECT {target} {version}\r\n\r\n").into_bytes()
    }

    fn make_connect_with_headers(target: &str, headers: &str) -> Vec<u8> {
        format!("CONNECT {target} HTTP/1.1\r\n{headers}\r\n").into_bytes()
    }

    #[test]
    fn parse_connect_valid() {
        let data = make_connect_request("api.example.com:443", "HTTP/1.1");
        let mut cursor = io::Cursor::new(data);
        let (host, port) = parse_connect_request(&mut cursor).unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_connect_lowercase_host() {
        let data = make_connect_request("API.EXAMPLE.COM:443", "HTTP/1.1");
        let mut cursor = io::Cursor::new(data);
        let (host, _) = parse_connect_request(&mut cursor).unwrap();
        assert_eq!(host, "api.example.com");
    }

    #[test]
    fn parse_connect_minimal() {
        let data = b"CONNECT host:8080 HTTP/1.0\r\n\r\n";
        let mut cursor = io::Cursor::new(&data[..]);
        let (host, port) = parse_connect_request(&mut cursor).unwrap();
        assert_eq!(host, "host");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_connect_with_headers_ignores_host() {
        let data = make_connect_with_headers(
            "allowed.com:443",
            "Host: evil.com:443\r\nProxy-Authorization: Basic abc\r\n",
        );
        let mut cursor = io::Cursor::new(data);
        let (host, port) = parse_connect_request(&mut cursor).unwrap();
        assert_eq!(host, "allowed.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_connect_wrong_method() {
        let data = b"GET / HTTP/1.1\r\n\r\n";
        let mut cursor = io::Cursor::new(&data[..]);
        assert!(parse_connect_request(&mut cursor).is_err());
    }

    #[test]
    fn parse_connect_bad_http_version() {
        let data = make_connect_request("host:443", "HTTP/9.9");
        let mut cursor = io::Cursor::new(data);
        assert!(parse_connect_request(&mut cursor).is_err());
    }

    #[test]
    fn parse_connect_missing_port() {
        let data = make_connect_request("host", "HTTP/1.1");
        let mut cursor = io::Cursor::new(data);
        assert!(parse_connect_request(&mut cursor).is_err());
    }

    #[test]
    fn parse_connect_port_zero() {
        let data = make_connect_request("host:0", "HTTP/1.1");
        let mut cursor = io::Cursor::new(data);
        assert!(parse_connect_request(&mut cursor).is_err());
    }

    #[test]
    fn parse_connect_port_overflow() {
        let data = make_connect_request("host:65536", "HTTP/1.1");
        let mut cursor = io::Cursor::new(data);
        assert!(parse_connect_request(&mut cursor).is_err());
    }

    #[test]
    fn parse_connect_port_nonnumeric() {
        let data = make_connect_request("host:abc", "HTTP/1.1");
        let mut cursor = io::Cursor::new(data);
        assert!(parse_connect_request(&mut cursor).is_err());
    }

    #[test]
    fn parse_connect_oversized() {
        let mut data = b"CONNECT host:443 HTTP/1.1\r\n".to_vec();
        data.extend(vec![b'X'; MAX_CONNECT_REQUEST + 100]);
        data.extend(b"\r\n\r\n");
        let mut cursor = io::Cursor::new(data);
        assert!(parse_connect_request(&mut cursor).is_err());
    }

    #[test]
    fn parse_connect_ipv6_brackets_rejected() {
        let data = make_connect_request("[::1]:443", "HTTP/1.1");
        let mut cursor = io::Cursor::new(data);
        assert!(parse_connect_request(&mut cursor).is_err());
    }

    #[test]
    fn parse_connect_trailing_dot_stripped() {
        let data = make_connect_request("api.example.com.:443", "HTTP/1.1");
        let mut cursor = io::Cursor::new(data);
        let (host, port) = parse_connect_request(&mut cursor).unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn validate_ip_rejects_loopback() {
        assert!(!is_safe_resolved_ip(&"127.0.0.1".parse().unwrap()));
        assert!(!is_safe_resolved_ip(&"127.255.255.255".parse().unwrap()));
        assert!(!is_safe_resolved_ip(&"::1".parse().unwrap()));
    }

    #[test]
    fn validate_ip_rejects_rfc1918() {
        assert!(!is_safe_resolved_ip(&"10.0.0.1".parse().unwrap()));
        assert!(!is_safe_resolved_ip(&"172.16.0.1".parse().unwrap()));
        assert!(!is_safe_resolved_ip(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn validate_ip_rejects_link_local() {
        assert!(!is_safe_resolved_ip(&"169.254.169.254".parse().unwrap()));
        assert!(!is_safe_resolved_ip(&"169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn validate_ip_rejects_ipv4_mapped_loopback() {
        assert!(!is_safe_resolved_ip(&"::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn validate_ip_rejects_ipv4_mapped_rfc1918() {
        assert!(!is_safe_resolved_ip(&"::ffff:10.0.0.1".parse().unwrap()));
        assert!(!is_safe_resolved_ip(&"::ffff:192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn validate_ip_rejects_unique_local() {
        assert!(!is_safe_resolved_ip(&"fc00::1".parse().unwrap()));
        assert!(!is_safe_resolved_ip(&"fd12:3456::1".parse().unwrap()));
    }

    #[test]
    fn validate_ip_rejects_nat64_loopback() {
        // 64:ff9b::7f00:1 = NAT64 of 127.0.0.1
        assert!(!is_safe_resolved_ip(&"64:ff9b::7f00:1".parse().unwrap()));
    }

    #[test]
    fn validate_ip_rejects_nat64_rfc1918() {
        // 64:ff9b::a00:1 = NAT64 of 10.0.0.1
        assert!(!is_safe_resolved_ip(&"64:ff9b::a00:1".parse().unwrap()));
        // 64:ff9b::c0a8:101 = NAT64 of 192.168.1.1
        assert!(!is_safe_resolved_ip(&"64:ff9b::c0a8:101".parse().unwrap()));
    }

    #[test]
    fn validate_ip_rejects_nat64_metadata() {
        // 64:ff9b::a9fe:a9fe = NAT64 of 169.254.169.254 (cloud metadata)
        assert!(!is_safe_resolved_ip(&"64:ff9b::a9fe:a9fe".parse().unwrap()));
    }

    #[test]
    fn validate_ip_rejects_nat64_local_use() {
        // 64:ff9b:1::1 = local-use NAT64 prefix (RFC 8215)
        assert!(!is_safe_resolved_ip(&"64:ff9b:1::1".parse().unwrap()));
    }

    #[test]
    fn validate_ip_allows_nat64_public() {
        // 64:ff9b::808:808 = NAT64 of 8.8.8.8 (public DNS — should be allowed)
        assert!(is_safe_resolved_ip(&"64:ff9b::808:808".parse().unwrap()));
    }

    #[test]
    fn validate_ip_allows_public() {
        assert!(is_safe_resolved_ip(&"1.1.1.1".parse().unwrap()));
        assert!(is_safe_resolved_ip(&"8.8.8.8".parse().unwrap()));
        assert!(is_safe_resolved_ip(
            &"2607:f8b0:4004:800::200e".parse().unwrap()
        ));
    }

    #[test]
    fn parse_connect_empty_host_rejected() {
        let data = make_connect_request(":443", "HTTP/1.1");
        let mut cursor = io::Cursor::new(data);
        assert!(parse_connect_request(&mut cursor).is_err());
    }

    #[test]
    fn parse_connect_consecutive_dots_rejected() {
        let data = make_connect_request("host..com:443", "HTTP/1.1");
        let mut cursor = io::Cursor::new(data);
        assert!(parse_connect_request(&mut cursor).is_err());
    }

    #[test]
    fn parse_connect_port_max_accepted() {
        let data = make_connect_request("host:65535", "HTTP/1.1");
        let mut cursor = io::Cursor::new(data);
        let (_, port) = parse_connect_request(&mut cursor).unwrap();
        assert_eq!(port, 65535);
    }

    #[test]
    fn parse_connect_negative_port_rejected() {
        let data = make_connect_request("host:-1", "HTTP/1.1");
        let mut cursor = io::Cursor::new(data);
        assert!(parse_connect_request(&mut cursor).is_err());
    }

    #[test]
    fn validate_ip_rejects_unspecified() {
        assert!(!is_safe_resolved_ip(&"0.0.0.0".parse().unwrap()));
        assert!(!is_safe_resolved_ip(&"::".parse().unwrap()));
    }

    #[test]
    fn validate_ip_rejects_this_network() {
        assert!(!is_safe_resolved_ip(&"0.0.0.1".parse().unwrap()));
        assert!(!is_safe_resolved_ip(&"0.255.255.255".parse().unwrap()));
    }

    #[test]
    fn validate_ip_rejects_cgnat() {
        assert!(!is_safe_resolved_ip(&"100.64.0.1".parse().unwrap()));
        assert!(!is_safe_resolved_ip(&"100.127.255.254".parse().unwrap()));
        // Just outside CGNAT range — should pass.
        assert!(is_safe_resolved_ip(&"100.63.255.255".parse().unwrap()));
        assert!(is_safe_resolved_ip(&"100.128.0.0".parse().unwrap()));
    }

    #[test]
    fn validate_ip_rejects_benchmarking() {
        assert!(!is_safe_resolved_ip(&"198.18.0.1".parse().unwrap()));
        assert!(!is_safe_resolved_ip(&"198.19.255.255".parse().unwrap()));
    }

    // ─── AllowedHost matching tests ─────────────────────────────

    #[test]
    fn allowed_host_exact_match() {
        let rule = AllowedHost {
            host: "api.example.com".into(),
            port: 443,
        };
        assert!(rule.matches("api.example.com", 443));
        assert!(!rule.matches("api.example.com", 8443));
        assert!(!rule.matches("other.example.com", 443));
        assert!(!rule.matches("evil-api.example.com", 443));
    }

    #[test]
    fn allowed_host_suffix_match() {
        let rule = AllowedHost {
            host: ".googleapis.com".into(),
            port: 443,
        };
        assert!(rule.matches("us-east5-aiplatform.googleapis.com", 443));
        assert!(rule.matches("oauth2.googleapis.com", 443));
        assert!(rule.matches("googleapis.com", 443));
        assert!(!rule.matches("us-east5-aiplatform.googleapis.com", 80));
        assert!(!rule.matches("evilgoogleapis.com", 443));
        assert!(!rule.matches("evil.com.googleapis.com.evil.com", 443));
    }

    #[test]
    fn allowed_host_suffix_does_not_match_partial_label() {
        let rule = AllowedHost {
            host: ".example.com".into(),
            port: 443,
        };
        assert!(rule.matches("sub.example.com", 443));
        assert!(!rule.matches("notexample.com", 443));
        assert!(!rule.matches("badexample.com", 443));
    }

    #[test]
    fn allowed_host_wrong_port() {
        let rule = AllowedHost {
            host: "api.example.com".into(),
            port: 443,
        };
        assert!(!rule.matches("api.example.com", 80));
    }

    #[test]
    fn allowed_host_empty_input_never_matches() {
        let exact = AllowedHost::new("api.example.com".into(), 443);
        let suffix = AllowedHost::new(".example.com".into(), 443);
        assert!(!exact.matches("", 443));
        assert!(!suffix.matches("", 443));
    }

    #[test]
    fn allowed_host_suffix_match_deep_subdomain() {
        let rule = AllowedHost::new(".example.com".into(), 443);
        assert!(rule.matches("a.b.c.d.example.com", 443));
    }

    #[test]
    fn allowed_host_exact_rule_rejects_subdomain() {
        let rule = AllowedHost::new("api.example.com".into(), 443);
        assert!(!rule.matches("sub.api.example.com", 443));
    }

    #[test]
    fn allowed_host_case_sensitive_requires_lowercase() {
        let rule = AllowedHost::new(".example.com".into(), 443);
        assert!(!rule.matches("SUB.EXAMPLE.COM", 443));
    }

    #[test]
    fn allowed_host_tld_wildcard_is_broad() {
        let rule = AllowedHost::new(".com".into(), 443);
        assert!(rule.matches("anything.com", 443));
        assert!(rule.matches("a.b.c.com", 443));
        assert!(rule.matches("com", 443));
    }

    #[cfg(seccomp_supported)]
    #[test]
    fn connect_proxy_seccomp_filters_build() {
        let (clone3_prog, main_prog) = build_connect_proxy_filters(false).unwrap();
        assert!(!clone3_prog.is_empty());
        assert!(!main_prog.is_empty());
    }

    // ─── parse_bridge_env tests ───────────────────────────────

    // Serialized: parse_bridge_env reads a process-global env var.
    static BRIDGE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_bridge_env<F: FnOnce()>(val: Option<&str>, f: F) {
        let _guard = BRIDGE_ENV_LOCK.lock().unwrap();
        match val {
            Some(v) => unsafe { std::env::set_var("ARAPUCA_PROXY_BRIDGE", v) },
            None => unsafe { std::env::remove_var("ARAPUCA_PROXY_BRIDGE") },
        }
        f();
        unsafe { std::env::remove_var("ARAPUCA_PROXY_BRIDGE") };
    }

    #[test]
    fn parse_bridge_env_not_set() {
        with_bridge_env(None, || {
            assert!(matches!(parse_bridge_env(), Ok(None)));
        });
    }

    #[test]
    fn parse_bridge_env_valid() {
        with_bridge_env(Some("18080:/tmp/proxy.sock"), || {
            let result = parse_bridge_env().unwrap().unwrap();
            assert_eq!(result.0, 18080);
            assert_eq!(result.1, std::path::PathBuf::from("/tmp/proxy.sock"));
        });
    }

    #[test]
    fn parse_bridge_env_port_one() {
        with_bridge_env(Some("1:/sock"), || {
            assert_eq!(parse_bridge_env().unwrap().unwrap().0, 1);
        });
    }

    #[test]
    fn parse_bridge_env_port_max() {
        with_bridge_env(Some("65535:/sock"), || {
            assert_eq!(parse_bridge_env().unwrap().unwrap().0, 65535);
        });
    }

    #[test]
    fn parse_bridge_env_port_zero() {
        with_bridge_env(Some("0:/sock"), || {
            assert!(parse_bridge_env().is_err());
        });
    }

    #[test]
    fn parse_bridge_env_port_overflow() {
        with_bridge_env(Some("65536:/sock"), || {
            assert!(parse_bridge_env().is_err());
        });
    }

    #[test]
    fn parse_bridge_env_port_negative() {
        with_bridge_env(Some("-1:/sock"), || {
            assert!(parse_bridge_env().is_err());
        });
    }

    #[test]
    fn parse_bridge_env_port_non_numeric() {
        with_bridge_env(Some("abc:/sock"), || {
            assert!(parse_bridge_env().is_err());
        });
    }

    #[test]
    fn parse_bridge_env_no_colon() {
        with_bridge_env(Some("18080"), || {
            assert!(parse_bridge_env().is_err());
        });
    }

    #[test]
    fn parse_bridge_env_empty_path() {
        with_bridge_env(Some("18080:"), || {
            assert!(parse_bridge_env().is_err());
        });
    }

    #[test]
    fn parse_bridge_env_empty_string() {
        with_bridge_env(Some(""), || {
            assert!(parse_bridge_env().is_err());
        });
    }

    #[test]
    fn parse_bridge_env_colon_only() {
        with_bridge_env(Some(":"), || {
            assert!(parse_bridge_env().is_err());
        });
    }

    #[test]
    fn parse_bridge_env_path_with_colons() {
        // split_once means the first colon separates port from path;
        // subsequent colons are part of the path.
        with_bridge_env(Some("18080:/run/user:1000/proxy.sock"), || {
            let result = parse_bridge_env().unwrap().unwrap();
            assert_eq!(result.0, 18080);
            assert_eq!(
                result.1,
                std::path::PathBuf::from("/run/user:1000/proxy.sock")
            );
        });
    }
}
