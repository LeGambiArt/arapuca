//! Integration tests for the Unix socket connect policy
//! (`--deny-privileged-unix-sockets`): the unotify connect broker.
//!
//! The broker needs a supervisor that can inspect the target, which on
//! Yama `ptrace_scope=1` hosts requires a user namespace. The positive
//! tests therefore run under `--deny-network` (which enables a user+
//! network namespace); the fail-closed test covers the opposite
//! configuration.

#![cfg(unix)]

use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;

fn arapuca_bin() -> PathBuf {
    // Compile-time location of the binary built by this package:
    // robust to cargo's test-binary layout (deps/ vs build/out/),
    // which differs across cargo versions.
    PathBuf::from(env!("CARGO_BIN_EXE_arapuca"))
}

fn netns_root_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--net", "--map-root-user", "--", "/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn python3_available() -> bool {
    Command::new("python3")
        .arg("-c")
        .arg("pass")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(target_os = "linux")]
fn yama_scope() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Yama scope 3 denies ptrace unconditionally — even a capful
/// supervisor inside a user namespace cannot inspect the target, so
/// no unotify-dependent test can run. Scopes 0-2 work under the
/// netns tests' user namespace (caps bypass scope 2).
fn yama_scope_is_absolute() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().parse::<u32>().unwrap_or(0) >= 3)
        .unwrap_or(false)
}

/// Run a command in the sandbox with the UDS policy active (inside a
/// user+network namespace so the supervisor can inspect the target on
/// Yama hosts). `extra_args` carries policy-specific flags.
fn run_with_policy(extra_args: &[&str], target: &str) -> std::process::Output {
    let mut cmd = Command::new(arapuca_bin());
    cmd.args([
        "run",
        "--deny-network",
        "--seccomp",
        "baseline",
        "--deny-privileged-unix-sockets",
    ])
    .args(extra_args)
    .arg("--")
    .arg("/usr/bin/python3")
    .arg("-c")
    .arg(target);
    cmd.output().unwrap()
}

/// A listener thread that accepts one connection (with a deadline —
/// denied-connection tests must not hang on accept), echoes the data
/// it receives, and reports what it saw.
struct EchoListener {
    path: PathBuf,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<(usize, Vec<u8>)>>,
}

impl EchoListener {
    fn spawn(dir: &std::path::Path, name: &str) -> Self {
        let path = dir.join(name);
        let listener = UnixListener::bind(&path).expect("bind test listener");
        listener
            .set_nonblocking(true)
            .expect("set listener nonblocking");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut received = Vec::new();
            // Backstop deadline for expected connections; the stop
            // flag (set by finish()) ends the wait early when no
            // connection is expected, e.g. after a denied connect.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut conn = loop {
                match listener.accept() {
                    Ok((conn, _)) => break conn,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if flag.load(std::sync::atomic::Ordering::Relaxed)
                            || std::time::Instant::now() > deadline
                        {
                            return (0, Vec::new());
                        }
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(_) => return (0, Vec::new()),
                }
            };
            conn.set_nonblocking(false).ok();
            conn.set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .ok();
            let mut buf = [0u8; 4096];
            if let Ok(n) = conn.read(&mut buf) {
                received.extend_from_slice(&buf[..n]);
                let _ = conn.write_all(b"ack");
            }
            (received.len(), received)
        });
        Self {
            path,
            stop,
            handle: Some(handle),
        }
    }

    fn finish(&mut self) -> (usize, Vec<u8>) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.handle
            .take()
            .expect("listener handle")
            .join()
            .expect("listener thread")
    }
}

#[test]
fn uds_policy_allows_ordinary_socket_and_data_flows() {
    if !netns_root_available() || !python3_available() {
        eprintln!("skipping: requires unshare userns and python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies all ptrace (reboot to restore)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut listener = EchoListener::spawn(dir.path(), "allowed.sock");
    let script = format!(
        r#"
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect({path:?})
s.sendall(b"hello-broker")
assert s.recv(64) == b"ack"
print("ALLOW_OK")
"#,
        path = listener.path.display().to_string()
    );
    let out = run_with_policy(&[], &script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("ALLOW_OK"),
        "allowed connect should work end-to-end: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (n, data) = listener.finish();
    assert_eq!(n, b"hello-broker".len());
    assert_eq!(&data, b"hello-broker");
}

#[test]
fn uds_policy_denies_deny_root_with_eacces() {
    if !netns_root_available() || !python3_available() {
        eprintln!("skipping: requires unshare userns and python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies all ptrace (reboot to restore)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut listener = EchoListener::spawn(dir.path(), "privileged.sock");
    let script = format!(
        r#"
import socket, errno
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
rc = s.connect_ex({path:?})
print("RC", rc)
assert rc == errno.EACCES, rc
print("DENY_OK")
"#,
        path = listener.path.display().to_string()
    );
    let root = dir.path().display().to_string();
    let out = run_with_policy(&["--unix-socket-deny-root", &root], &script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("DENY_OK"),
        "denied connect should report EACCES: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The listener must never see a connection or data: the target's
    // socket is never connected on the deny path (ADDFD design).
    let (n, _) = listener.finish();
    assert_eq!(n, 0, "listener must not receive data on a denied connect");
}

#[test]
fn uds_policy_denies_non_dumpable_target() {
    // PR_SET_DUMPABLE(0) defeats /proc/pid/mem inspection and
    // pidfd_getfd; the fail-closed matrix must deny the connect
    // rather than fail open. (Under the policy the prctl itself is
    // also blocked with EPERM by seccomp, so this exercises whichever
    // layer fires first — both must deny.)
    if !netns_root_available() || !python3_available() {
        eprintln!("skipping: requires unshare userns and python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies all ptrace (reboot to restore)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut listener = EchoListener::spawn(dir.path(), "priv.sock");
    let script = format!(
        r#"
import socket, errno, ctypes
libc = ctypes.CDLL(None, use_errno=True)
# Best effort: if the seccomp layer already blocks it, the connect
# must still be denied below.
libc.prctl(4, 0)  # PR_SET_DUMPABLE, 0
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
rc = s.connect_ex({path:?})
print("RC", rc)
assert rc in (errno.EACCES, errno.EPERM), rc
print("DUMPABLE_DENY_OK")
"#,
        path = listener.path.display().to_string()
    );
    let root = dir.path().display().to_string();
    let out = run_with_policy(&["--unix-socket-deny-root", &root], &script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("DUMPABLE_DENY_OK"),
        "non-dumpable target must be denied: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (n, _) = listener.finish();
    assert_eq!(n, 0);
}

#[test]
fn uds_policy_sibling_writer_never_reaches_denied_peer() {
    // TOCTOU regression, sibling-writer variant: while thread A
    // connects to a denied root, thread B spins write() on the same
    // fd. With the ADDFD design the original socket is never
    // connected, so the writes fail and the listener receives
    // nothing.
    if !netns_root_available() || !python3_available() {
        eprintln!("skipping: requires unshare userns and python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies all ptrace (reboot to restore)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut listener = EchoListener::spawn(dir.path(), "target.sock");
    let script = format!(
        r#"
import ctypes, threading, time

libc = ctypes.CDLL(None, use_errno=True)
AF_UNIX = 1
SOCK_STREAM = 1
path = {path:?}

fd = libc.socket(AF_UNIX, SOCK_STREAM, 0)
assert fd >= 0

stop = threading.Event()
sent = threading.Event()

def writer():
    payload = b"GET /escape HTTP/1.0\r\n\r\n"
    while not stop.is_set():
        if libc.write(fd, payload, len(payload)) > 0:
            sent.set()
        time.sleep(0.0005)

t = threading.Thread(target=writer)
t.start()

# Connect attempts to the denied socket: each is brokered and denied;
# the spinning writer must never see a connected fd.
denied = 0
for _ in range(50):
    rc = libc.connect(fd, path.encode() + b"\0" + b"\0" * 100, 110)
    if rc == 0:
        print("UNEXPECTED_CONNECT")
        break
    denied += 1
stop.set()
t.join()
print("DENIED", denied, "SENT", sent.is_set())
"#,
        path = listener.path.display().to_string()
    );
    let root = dir.path().display().to_string();
    let out = run_with_policy(&["--unix-socket-deny-root", &root], &script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("DENIED 50"),
        "all 50 connect attempts must be denied: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !stdout.contains("SENT True"),
        "sibling writer must never deliver data: {stdout}"
    );
    let (n, _) = listener.finish();
    assert_eq!(n, 0, "listener must never receive the writer's bytes");
}

#[test]
fn uds_policy_buffer_rewrite_race_connects_benign_socket_only() {
    // TOCTOU regression, buffer-rewrite variant: the sockaddr buffer
    // is rewritten to the denied path while the connect is in flight.
    // The broker dials its own snapshot copy, so every connect goes
    // to the benign path the supervisor saw; the denied listener
    // never sees a connection.
    if !netns_root_available() || !python3_available() {
        eprintln!("skipping: requires unshare userns and python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies all ptrace (reboot to restore)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // The denied root covers the whole tempdir; the benign listener
    // lives in a sibling directory outside it.
    let denied_dir = tempfile::tempdir().unwrap();
    let mut benign = EchoListener::spawn(dir.path(), "benign.sock");
    let mut denied = EchoListener::spawn(denied_dir.path(), "denied.sock");

    let script = format!(
        r#"
import ctypes, threading

libc = ctypes.CDLL(None, use_errno=True)
AF_UNIX = 1
SOCK_STREAM = 1
benign = {benign:?}
denied = {denied:?}

class Sockaddr(ctypes.Structure):
    _fields_ = [("sun_family", ctypes.c_uint16),
                ("sun_path", ctypes.c_char * 108)]

def connect_spin(addr_buf, rewriter):
    ok = 0
    for _ in range(50):
        addr_buf.sun_path = benign.encode()
        t = threading.Thread(target=rewriter, args=(addr_buf,))
        t.start()
        rc = libc.connect(fd, ctypes.byref(addr_buf), ctypes.sizeof(Sockaddr))
        if rc == 0:
            libc.close(fd2[0]) if False else None
            ok += 1
        t.join()
    print("CONNECTED", ok)

# One fd reused across attempts; on success the broker replaced it
# with a connected socket, so recreate it each iteration.
connected = 0
for _ in range(50):
    fd = libc.socket(AF_UNIX, SOCK_STREAM, 0)
    addr = Sockaddr()
    addr.sun_path = benign.encode()

    def rewrite(a):
        # Spin the path between benign and denied while the syscall
        # is in flight.
        for _ in range(200):
            a.sun_path = denied.encode()

    t = threading.Thread(target=rewrite, args=(addr,))
    t.start()
    rc = libc.connect(fd, ctypes.byref(addr), ctypes.sizeof(Sockaddr))
    t.join()
    if rc == 0:
        connected += 1
    libc.close(fd)
print("CONNECTED", connected)
"#,
        benign = benign.path.display().to_string(),
        denied = denied.path.display().to_string()
    );
    let root = denied_dir.path().display().to_string();
    let out = run_with_policy(&["--unix-socket-deny-root", &root], &script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let connected: usize = stdout
        .lines()
        .find_map(|l| l.strip_prefix("CONNECTED ").and_then(|v| v.parse().ok()))
        .unwrap_or(0);
    assert!(
        out.status.success(),
        "script must complete: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Connects that completed must have gone to the benign listener
    // (or failed); the denied listener must be untouched.
    let (denied_n, _) = denied.finish();
    assert_eq!(
        denied_n, 0,
        "buffer-rewrite race must never reach the denied socket: {stdout}"
    );
    let (benign_n, _) = benign.finish();
    let _ = connected;
    let _ = benign_n; // benign may or may not accept depending on timing
}

#[test]
fn uds_policy_unsupported_family_denies_without_killing_supervisor() {
    // A connect() on a socket of a family the broker does not dial
    // (AF_NETLINK) must be denied cleanly. The supervisor's own
    // seccomp family-filters socket(), so attempting the dial would
    // kill the supervisor and convert every subsequent connect to
    // ENOSYS — deny-direction, but a self-inflicted single point of
    // failure. Regression: the target must get EACCES (not ENOSYS)
    // and an ordinary UDS connect must still work afterwards.
    if !netns_root_available() || !python3_available() {
        eprintln!("skipping: requires unshare userns and python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies all ptrace (reboot to restore)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut listener = EchoListener::spawn(dir.path(), "after.sock");
    let script = format!(
        r#"
import socket, ctypes, errno

libc = ctypes.CDLL(None, use_errno=True)

class SockaddrNl(ctypes.Structure):
    _fields_ = [("nl_family", ctypes.c_uint16), ("nl_pad", ctypes.c_uint16),
                ("nl_pid", ctypes.c_uint32), ("nl_groups", ctypes.c_uint32)]

nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
sa = SockaddrNl()
sa.nl_family = 16
rc = libc.connect(nl.fileno(), ctypes.byref(sa), ctypes.sizeof(SockaddrNl))
err = ctypes.get_errno()
print("NETLINK_RC", rc, "ERRNO", err)
assert err == errno.EACCES, err

# The supervisor must still be alive: an ordinary UDS connect works.
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect({path:?})
s.sendall(b"still-alive")
assert s.recv(64) == b"ack"
print("SURVIVOR_OK")
"#,
        path = listener.path.display().to_string()
    );
    let out = run_with_policy(&[], &script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("SURVIVOR_OK"),
        "supervisor must survive an unsupported-family connect: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (n, data) = listener.finish();
    assert_eq!(&data, b"still-alive");
    assert_eq!(n, b"still-alive".len());
}

#[test]
fn uds_policy_flag_validation() {
    // Deny roots require the policy.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().display().to_string();
    let out = Command::new(arapuca_bin())
        .args(["run", "--unix-socket-deny-root", &root, "--", "/bin/true"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(125), "stderr: {stderr}");
    assert!(
        stderr.contains("unix_socket_deny_roots requires"),
        "{stderr}"
    );

    // Roots must be absolute.
    let out = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-privileged-unix-sockets",
            "--unix-socket-deny-root",
            "relative/path",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(125), "stderr: {stderr}");
    assert!(stderr.contains("must be absolute"), "{stderr}");
}

// ─── Broker INET paths under the policy ──────────────────────────

#[test]
fn uds_policy_broker_inet_allows_bridge_dns() {
    // The broker's INET allow path: a UDP connect to the DNS capture
    // address (127.0.0.1:53) is checked against the bridge allowlist,
    // dialed, and delivered — the delivered socket must be usable.
    if !netns_root_available() || !python3_available() {
        eprintln!("skipping: requires unshare userns and python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies all ptrace (reboot to restore)");
        return;
    }
    let script = r#"
import socket
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rc = u.connect_ex(("127.0.0.1", 53))
print("UDP_CONNECT", rc)
assert rc == 0, rc
print("PEER", u.getpeername()[1])
"#;
    let out = run_with_policy(&[], script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("UDP_CONNECT 0") && stdout.contains("PEER 53"),
        "broker must deliver a working INET socket for the DNS bridge: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn uds_policy_broker_inet_denies_nonbridge_before_dial() {
    // The broker's INET deny path: with network enforcement active,
    // a connect to a non-bridge address is answered ECONNREFUSED
    // BEFORE the supervisor dials. Discriminator: the target listens
    // on the address itself — without the policy the kernel accepts
    // the local connection; with it, the broker denies.
    if !netns_root_available() || !python3_available() {
        eprintln!("skipping: requires unshare userns and python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies all ptrace (reboot to restore)");
        return;
    }
    let script = r#"
import socket, errno
lst = socket.socket()
lst.bind(("127.0.0.1", 45678))
lst.listen(1)
c = socket.socket()
rc = c.connect_ex(("127.0.0.1", 45678))
print("NONBRIDGE", rc)
assert rc == errno.ECONNREFUSED, rc
"#;
    let out = run_with_policy(&[], script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("NONBRIDGE 111"),
        "broker must deny non-bridge INET connects under enforcement: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ─── selfexec twin path ──────────────────────────────────────────

/// Drive the selfexec trampoline directly (the entry go-arapuca's C
/// constructor calls): fork, enter a user+network namespace (so the
/// supervisor can inspect the target on Yama hosts — the same
/// configuration the wrapper-binary path gets from `unshare`), set
/// the wrapper environment, and call
/// `arapuca_handle_selfexec_if_wrapper`. The child execs into
/// python3 under the full sandbox (Landlock + seccomp + broker).
#[cfg(target_os = "linux")]
fn run_selfexec(unotify_config: Option<&str>, script: &str) -> (Option<i32>, String) {
    use std::ffi::CString;

    let mut pipe_fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // SAFETY: single-threaded fork child; fds are valid.
        unsafe {
            libc::close(pipe_fds[0]);
            libc::dup2(pipe_fds[1], 1);
            libc::close(pipe_fds[1]);
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0 {
                eprintln!("selfexec test: unshare failed");
                libc::_exit(99);
            }
        }
        // Set the wrapper environment with libc setenv, NOT
        // std::env::set_var: this child was forked from the
        // multi-threaded test harness, and the Rust env rwlock may
        // have been read-held by another harness thread at fork
        // time — a write in this child would then wait forever for a
        // reader that exists only in the parent process. glibc's own
        // env lock is never taken by Rust's env readers, so libc
        // setenv cannot inherit a held lock here.
        //
        // SAFETY: single-threaded post-fork child; glibc setenv with
        // NUL-terminated literals.
        unsafe {
            libc::setenv(c"ARAPUCA_WRAPPER".as_ptr(), c"1".as_ptr(), 1);
            libc::setenv(
                c"ARAPUCA_READ_PATHS".as_ptr(),
                c"/usr:/lib:/lib64:/bin:/sbin:/etc".as_ptr(),
                1,
            );
            libc::setenv(c"ARAPUCA_SECCOMP_PROFILE".as_ptr(), c"baseline".as_ptr(), 1);
            libc::setenv(c"ARAPUCA_ALLOW_EXEC".as_ptr(), c"1".as_ptr(), 1);
            // Direct selfexec invocation: no caller extra_fds cross.
            libc::setenv(c"ARAPUCA_TARGET_FDS".as_ptr(), c"0".as_ptr(), 1);
            if let Some(cfg) = unotify_config {
                let cfg_c = CString::new(cfg).unwrap();
                libc::setenv(c"ARAPUCA_UNOTIFY_CONFIG".as_ptr(), cfg_c.as_ptr(), 1);
            }
        }
        let exe = std::env::current_exe().expect("current exe");
        let argv: Vec<CString> = vec![
            CString::new(exe.to_string_lossy().as_bytes().to_vec()).unwrap(),
            CString::new("--").unwrap(),
            CString::new("/usr/bin/python3").unwrap(),
            CString::new("-c").unwrap(),
            CString::new(script).unwrap(),
        ];
        let mut cargv: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
        cargv.push(std::ptr::null());
        // Never returns: applies the sandbox and execs python3.
        // (Safe by signature; it _exit()s or execve()s internally.)
        arapuca::selfexec::arapuca_handle_selfexec_if_wrapper(
            (cargv.len() - 1) as libc::c_int,
            cargv.as_ptr(),
        );
        unreachable!();
    }
    // Parent: capture stdout, reap.
    // SAFETY: read end of a valid pipe.
    unsafe { libc::close(pipe_fds[1]) };
    let mut output = String::new();
    {
        use std::io::Read;
        use std::os::unix::io::FromRawFd;
        let mut f = unsafe { std::fs::File::from_raw_fd(pipe_fds[0]) };
        let _ = f.read_to_string(&mut output);
    }
    let mut status: libc::c_int = 0;
    // SAFETY: pid is a valid fork child.
    assert!(unsafe { libc::waitpid(pid, &mut status, 0) } > 0);
    let code = if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else {
        None
    };
    (code, output)
}

#[cfg(target_os = "linux")]
#[test]
fn uds_policy_selfexec_path_brokers_connects() {
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies all ptrace (reboot to restore)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();

    // Allow case: ordinary socket connect works end-to-end through
    // the selfexec trampoline.
    let mut listener = EchoListener::spawn(dir.path(), "allowed.sock");
    let allow_script = format!(
        r#"
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect({path:?})
s.sendall(b"selfexec")
assert s.recv(64) == b"ack"
print("SELFEXEC_ALLOW_OK")
"#,
        path = listener.path.display().to_string()
    );
    // Build the config with the real producer (contract fidelity).
    let allow_profile = arapuca::Profile {
        unix_socket_connect_policy: arapuca::UnixSocketConnectPolicy::DenyPrivileged,
        ..Default::default()
    };
    let (_, cfg) = arapuca::env::unotify_env(&allow_profile)
        .expect("policy active must produce a unotify config");
    let (code, stdout) = run_selfexec(Some(&cfg), &allow_script);
    assert!(
        code == Some(0) && stdout.contains("SELFEXEC_ALLOW_OK"),
        "selfexec allow path: code={code:?} stdout={stdout}"
    );
    let (n, data) = listener.finish();
    assert_eq!(&data, b"selfexec");
    assert_eq!(n, b"selfexec".len());

    // Deny case: the deny root is enforced through the same path.
    let denied_dir = tempfile::tempdir().unwrap();
    let mut denied_listener = EchoListener::spawn(denied_dir.path(), "privileged.sock");
    let deny_script = format!(
        r#"
import socket, errno
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
rc = s.connect_ex({path:?})
print("SELFEXEC_DENY", rc)
assert rc == errno.EACCES, rc
"#,
        path = denied_listener.path.display().to_string()
    );
    let deny_profile = arapuca::Profile {
        unix_socket_connect_policy: arapuca::UnixSocketConnectPolicy::DenyPrivileged,
        unix_socket_deny_roots: vec![denied_dir.path().to_path_buf()],
        ..Default::default()
    };
    let (_, cfg) = arapuca::env::unotify_env(&deny_profile).unwrap();
    let (code, stdout) = run_selfexec(Some(&cfg), &deny_script);
    assert!(
        code == Some(0) && stdout.contains("SELFEXEC_DENY 13"),
        "selfexec deny path: code={code:?} stdout={stdout}"
    );
    let (n, _) = denied_listener.finish();
    assert_eq!(n, 0, "denied listener must see nothing");
}

// ─── Typed audit event mapping (requires the serde feature) ──────

#[cfg(feature = "serde")]
#[test]
fn uds_policy_emits_unix_socket_blocked_event() {
    use arapuca::audit::{AuditSink, AuditVerbosity};
    use arapuca::platform::{Sandbox as _, new};

    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    let denied_dir = tempfile::tempdir().unwrap();
    let sock_path = denied_dir.path().join("privileged.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

    #[derive(Default)]
    struct VecSink(std::sync::Mutex<Vec<arapuca::audit::AuditEvent>>);
    impl AuditSink for VecSink {
        fn emit(&self, event: arapuca::audit::AuditEvent) {
            self.0.lock().unwrap().push(event);
        }
    }
    let sink: std::sync::Arc<VecSink> = Default::default();
    let (read_paths, write_paths) = arapuca::env::default_sandbox_paths();
    let cfg = arapuca::Config {
        profile: arapuca::Profile {
            read_paths,
            write_paths,
            audit_network: true,
            use_netns: true,
            seccomp_profile: arapuca::SeccompProfile::Baseline,
            unix_socket_connect_policy: arapuca::UnixSocketConnectPolicy::DenyPrivileged,
            unix_socket_deny_roots: vec![denied_dir.path().to_path_buf()],
            ..Default::default()
        },
        socket_dir: std::path::PathBuf::new(),
        task_id: "uds-policy-audit-test".into(),
        phase: "test".into(),
        work_dir: None,
        stdin: None,
        stdout: None,
        stderr: None,
        extra_fds: Vec::new(),
        tty: false,
        network_proxy_socket: None,
        allowed_hosts: Vec::new(),
        env: Vec::new(),
        audit_sink: Some(std::sync::Arc::clone(&sink) as std::sync::Arc<dyn AuditSink>),
        audit_verbosity: AuditVerbosity::Standard,
        audit_principal: None,
        audit_correlation_id: None,
    };

    let script = format!(
        r#"
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
rc = s.connect_ex({path:?})
assert rc == 13, rc
"#,
        path = sock_path.display().to_string()
    );
    let sb = new().unwrap();
    let mut proc = sb
        .launch(&cfg, "/usr/bin/python3", &["-c", script.as_str()])
        .unwrap();
    let status = proc.wait().unwrap();
    proc.cleanup();
    assert!(status.success(), "script must complete");

    let events = sink.0.lock().unwrap();
    let blocked: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            arapuca::audit::AuditEvent::UnixSocketBlocked {
                path,
                syscall,
                detail,
                ..
            } => Some((path.clone(), syscall.clone(), detail.clone())),
            _ => None,
        })
        .collect();
    assert!(
        blocked.iter().any(|(p, s, d)| {
            p.ends_with("privileged.sock") && s == "connect" && d.as_deref() == Some("deny-root")
        }),
        "expected a UnixSocketBlocked event for the denied connect, got: {blocked:?}"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            arapuca::audit::AuditEvent::LayerApplied {
                layer: arapuca::audit::SandboxLayer::UnotifySupervisor,
                ..
            }
        )),
        "UnotifySupervisor layer must be reported applied"
    );
}

// ─── int 0x80 compat entry (arch-mismatch kill) ──────────────────

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn uds_policy_int80_connect_killed_by_arch_filter() {
    if !netns_root_available() {
        eprintln!("skipping: requires unshare userns");
        return;
    }
    // Compile a probe that issues connect() through int 0x80 (i386
    // compat entry, AUDIT_ARCH_I386). Bare, the kernel answers the
    // compat syscall (EINVAL from the 32-bit-truncated sockaddr
    // pointer — dispatch proven); under the sandbox it must be
    // killed in every profile × policy combination. The kill comes
    // from the arch-validation sequence seccompiler embeds at the
    // head of every generated filter (unconditional KILL_PROCESS on
    // AUDIT_ARCH mismatch — the mismatch_action parameter only
    // governs unmatched syscall numbers), plus the kill-on-mismatch
    // variant of the unotify BPF under the policy: the compat entry
    // can never reach the connect broker or the kernel's connect.
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("int80probe");
    let source = r#"
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, argv[1], sizeof sa.sun_path - 1);
    long rc;
    asm volatile("int $0x80"
                 : "=a"(rc)
                 : "a"(363L), "b"((long)fd), "c"((long)&sa), "d"((long)sizeof sa)
                 : "memory");
    if (rc == 0) { printf("INT80_CONNECTED\n"); return 0; }
    printf("INT80_ERR %ld\n", rc);
    return 1;
}
"#;
    let cc = std::process::Command::new("cc")
        .arg("-o")
        .arg(&probe)
        .arg("-x")
        .arg("c")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let mut cc = match cc {
        Ok(cc) => cc,
        Err(_) => {
            eprintln!("skipping: cc not available");
            return;
        }
    };
    use std::io::Write;
    cc.stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    assert!(cc.wait().unwrap().success(), "probe must compile");

    // Control: bare execution proves the compat entry dispatches.
    let out = Command::new(&probe)
        .arg("/nonexistent.sock")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("INT80_ERR"),
        "bare probe must reach the compat syscall: {stdout}"
    );

    // Under the sandbox, every combination must kill the compat entry.
    let dir2 = tempfile::tempdir().unwrap();
    for (seccomp_mode, policy) in [
        ("baseline", false),
        ("baseline", true),
        ("strict", false),
        ("strict", true),
    ] {
        let _ = std::fs::remove_file(dir2.path().join("target.sock"));
        let mut listener = EchoListener::spawn(dir2.path(), "target.sock");
        let target = listener.path.display().to_string();
        let mut cmd = Command::new("unshare");
        cmd.args(["--user", "--net", "--map-root-user", "--"])
            .arg(arapuca_bin())
            .args(["run", "--seccomp", seccomp_mode]);
        if policy {
            cmd.arg("--deny-privileged-unix-sockets");
        }
        cmd.arg("-v")
            .arg(format!("{}:ro", dir.path().display()))
            .arg("--")
            .arg(&probe)
            .arg(&target);
        let out = cmd.output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !out.status.success(),
            "compat-entry connect must fail the run ({seccomp_mode}/policy={policy}): {stdout}"
        );
        assert!(
            !stdout.contains("INT80_CONNECTED") && !stdout.contains("INT80_ERR"),
            "compat entry must be killed, not answered ({seccomp_mode}/policy={policy}): {stdout}"
        );
        let (n, _) = listener.finish();
        assert_eq!(
            n, 0,
            "listener must never see a compat-entry connect ({seccomp_mode}/policy={policy})"
        );
    }
}

// ─── Malformed unotify config fails closed ───────────────────────

#[cfg(seccomp_supported)]
#[test]
fn malformed_unotify_config_fails_closed() {
    for bad in ["uds,uds_deny_roots=", "udsx"] {
        let out = Command::new(arapuca_bin())
            .args(["--", "/bin/true"])
            .env("ARAPUCA_WRAPPER", "1")
            // Direct wrapper invocation: declare that no caller extra_fds cross.
            .env("ARAPUCA_TARGET_FDS", "0")
            .env("ARAPUCA_READ_PATHS", "/usr:/lib:/lib64:/bin")
            .env("ARAPUCA_UNOTIFY_CONFIG", bad)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(125),
            "malformed config {bad:?} must fail closed: {stderr}"
        );
        assert!(
            stderr.contains("malformed ARAPUCA_UNOTIFY_CONFIG"),
            "error must name the config: {stderr}"
        );
    }
}

// ─── Worker-thread connects ──────────────────────────────────────

#[test]
fn uds_policy_worker_thread_connects_brokered() {
    // Multi-threaded runtimes (node, JVM, Go) issue connects from
    // worker threads. seccomp notifications report the connecting
    // THREAD's id, and pidfd_open only accepts thread-group leaders,
    // so the broker must resolve the thread group before duplicating
    // the fd — otherwise every worker-thread connect is denied
    // EACCES regardless of the policy decision.
    if !netns_root_available() || !python3_available() {
        eprintln!("skipping: requires unshare userns and python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies all ptrace (reboot to restore)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();

    // Allowed socket, connected FROM a worker thread: must work
    // end-to-end with data flowing.
    let mut listener = EchoListener::spawn(dir.path(), "allowed.sock");
    let allow_script = format!(
        r#"
import socket, threading

result = dict()
def connector():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect({path:?})
    s.sendall(b"from-a-thread")
    result["recv"] = s.recv(64)
    result["err"] = None

t = threading.Thread(target=connector)
t.start()
t.join()
assert result["err"] is None
assert result["recv"] == b"ack", result
print("THREAD_ALLOW_OK")
"#,
        path = listener.path.display().to_string()
    );
    let out = run_with_policy(&[], &allow_script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("THREAD_ALLOW_OK"),
        "worker-thread connect to an allowed socket must work: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (n, data) = listener.finish();
    assert_eq!(&data, b"from-a-thread");
    assert_eq!(n, b"from-a-thread".len());

    // Denied root, connected from a worker thread: must be denied
    // by the POLICY (deny-root), not by a thread-id resolution
    // failure — the audit reason distinguishes them.
    let denied_dir = tempfile::tempdir().unwrap();
    let mut denied_listener = EchoListener::spawn(denied_dir.path(), "priv.sock");
    let deny_script = format!(
        r#"
import socket, threading, errno

result = dict()
def connector():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    result["rc"] = s.connect_ex({path:?})

t = threading.Thread(target=connector)
t.start()
t.join()
print("THREAD_DENY", result["rc"])
assert result["rc"] == errno.EACCES, result
"#,
        path = denied_listener.path.display().to_string()
    );
    let root = denied_dir.path().display().to_string();
    let out = run_with_policy(&["--unix-socket-deny-root", &root], &deny_script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("THREAD_DENY 13"),
        "worker-thread connect to a deny root must be denied by the policy: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (n, _) = denied_listener.finish();
    assert_eq!(n, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn builtin_deny_roots_cover_snap_lxd_and_incus() {
    // The list is a best-effort enumeration of root-equivalent daemon
    // sockets; this pins the entries whose absence was a review
    // finding (snap LXD and Incus bind outside the old deb-package
    // paths, and the README's LXD claim must hold for them too).
    let roots = arapuca::unotify::builtin_unix_deny_roots();
    for expected in [
        "/var/snap/lxd/common/lxd",
        "/var/lib/incus",
        "/run/incus",
        "/run/docker.sock",
        "/run/podman",
    ] {
        assert!(
            roots.iter().any(|r| r == expected),
            "builtin deny root missing: {expected}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn symlinked_deny_root_still_denies() {
    // The broker compares the peer against the listener's bind-time
    // path, which getpeername returns as the daemon wrote it — never
    // resolved. A root stored only in canonical form therefore never
    // matches a daemon that bound through a symlinked directory. Both
    // the literal and the resolved form must be stored.
    if !netns_root_available() || !python3_available() {
        eprintln!("skipping: requires unshare userns and python3");
        return;
    }
    // Inline gate: the yama_scope_is_absolute helper arrives with a
    // later commit; scope 3 denies the supervisor inspection outright.
    let yama_abs = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().parse::<u32>().unwrap_or(0) >= 3)
        .unwrap_or(false);
    if yama_abs {
        eprintln!("skipping: yama ptrace_scope=3 denies the supervisor inspection");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let sock = link.join("daemon.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

    let script = format!(
        r#"
import socket, errno
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
rc = s.connect_ex({path:?})
print("RC", rc)
assert rc == errno.EACCES, rc
print("SYMLINK_ROOT_DENIED")
"#,
        path = sock.display().to_string()
    );
    // Deny root named through the symlink: canonicalized it is
    // <dir>/real, but the daemon's bind literal is <dir>/link/...
    let out = run_with_policy_deny_root(&link.display().to_string(), &script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("SYMLINK_ROOT_DENIED"),
        "a deny root named through a symlink must still deny the \
         symlinked bind path: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(target_os = "linux")]
fn run_with_policy_deny_root(root: &str, target: &str) -> std::process::Output {
    let mut cmd = Command::new(arapuca_bin());
    cmd.args([
        "run",
        "--deny-network",
        "--seccomp",
        "baseline",
        "--deny-privileged-unix-sockets",
        "--unix-socket-deny-root",
        root,
    ])
    .arg("--")
    .arg("/usr/bin/python3")
    .arg("-c")
    .arg(target);
    cmd.output().unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn delivered_socket_survives_target_execve() {
    // The delivered socket must carry the TARGET socket's
    // close-on-exec state, read from fdinfo — not the supervisor's
    // pidfd_getfd copy, which the kernel always creates with CLOEXEC
    // and which made every delivered socket close at the target's
    // next exec. The target clears CLOEXEC (os.set_inheritable) and
    // execs a shell that writes through the socket.
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    // Inline gate: the yama_scope_is_absolute helper arrives with a
    // later commit; scope 3 denies the supervisor inspection outright.
    let yama_abs = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().parse::<u32>().unwrap_or(0) >= 3)
        .unwrap_or(false);
    if yama_abs {
        eprintln!("skipping: yama ptrace_scope=3 denies the supervisor inspection");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("exec.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    let received = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let received2 = std::sync::Arc::clone(&received);
    let _reader = std::thread::spawn(move || {
        if let Ok((conn, _)) = listener.accept() {
            use std::io::Read;
            let mut conn = conn;
            let mut buf = [0u8; 32];
            if let Ok(n) = conn.read(&mut buf) {
                if &buf[..n] == b"INHERITED" {
                    received2.store(n, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    });
    let script = format!(
        r#"
import os, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect({path:?})
# Clear CLOEXEC (PEP 446 sets it on every fd): the delivered socket
# must inherit this state, or the exec'd shell below gets EBADF.
os.set_inheritable(s.fileno(), True)
os.execv("/bin/sh", ["/bin/sh", "-c", "printf INHERITED >&3; exit 0"])
"#,
        path = sock_path.display().to_string()
    );
    let out = run_with_policy(&[], &script);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The reader thread races the process exit: wait for it, bounded.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut n = 0;
    while std::time::Instant::now() < deadline {
        n = received.load(std::sync::atomic::Ordering::Relaxed);
        if n == b"INHERITED".len() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        n == b"INHERITED".len(),
        "the exec'd child must write through the delivered socket \\
         (got {n} bytes; exit={:?}, stderr: {stderr})",
        out.status.code()
    );
}

// ─── Target capability scrub ─────────────────────────────────────

#[test]
fn target_is_capless_in_userns_at_exec() {
    // Under `unshare --user --map-root-user` the sandboxed target
    // would otherwise retain a full capability set in the user
    // namespace across exec — which bypasses PR_SET_DUMPABLE=0 and
    // Yama on every same-namespace process, including the unotify
    // supervisor whose allowlist permits connect(). The wrapper
    // scrubs the grant (SECBIT_NOROOT) before exec: the target must
    // report no effective capabilities.
    if !netns_root_available() || !python3_available() {
        eprintln!("skipping: requires unshare userns and python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies all ptrace (reboot to restore)");
        return;
    }
    let out = Command::new("unshare")
        .args(["--user", "--net", "--map-root-user", "--"])
        .arg(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--no-pid-ns",
            "--seccomp",
            "baseline",
            "--",
        ])
        .arg("/usr/bin/python3")
        .arg("-c")
        .arg(
            r#"
import re
status = open("/proc/self/status").read()
cap_eff = re.search(r"^CapEff:\s*(\w+)", status, re.M).group(1)
print("CAP_EFF", cap_eff)
assert int(cap_eff, 16) == 0, cap_eff
"#,
        )
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("CAP_EFF 0"),
        "target must be capless at exec: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn supervisor_mem_not_writable_by_capless_target() {
    // The companion assertion to the scrub: with --no-pid-ns and a
    // /proc-readable (baseline) sandbox, the target can enumerate
    // the arapuca processes (supervisor, bridge, relay) in /proc —
    // pidns does NOT hide them — but with the target capless and
    // the helpers non-dumpable, opening their /proc/<pid>/mem must
    // fail EACCES. Only meaningful when a supervisor actually runs
    // (Yama ptrace_scope <= 1, or the audit path forks one inside
    // the userns); at higher scopes the run fail-closes earlier and
    // the test degrades to asserting the target is capless.
    if !netns_root_available() || !python3_available() {
        eprintln!("skipping: requires unshare userns and python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies all ptrace (reboot to restore)");
        return;
    }
    let yama_scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
    let script = r#"
import os, re, errno

status = open("/proc/self/status").read()
cap_eff = int(re.search(r"^CapEff:\s*(\w+)", status, re.M).group(1), 16)
assert cap_eff == 0, cap_eff

checked = 0
denied = 0
for pid in os.listdir("/proc"):
    if not pid.isdigit():
        continue
    try:
        comm = open(f"/proc/{pid}/comm").read().strip()
    except OSError:
        continue
    if "arapuca" not in comm:
        continue
    try:
        fd = os.open(f"/proc/{pid}/mem", os.O_RDWR)
        os.close(fd)
        print("MEM_OPEN_OK", pid, comm)
    except OSError as e:
        assert e.errno == errno.EACCES, (pid, comm, e.errno)
        denied += 1
    checked += 1
print("ARAPUCA_PROCS", checked, "DENIED", denied)
"#;
    let out = Command::new("unshare")
        .args(["--user", "--net", "--map-root-user", "--"])
        .arg(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--no-pid-ns",
            "--seccomp",
            "baseline",
            "--",
        ])
        .arg("/usr/bin/python3")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if yama_scope >= 2 {
        // No supervisor can run (launch fail-closes under the
        // policy; audit-only paths skip it): the capless assertion
        // is all that can hold here.
        eprintln!("skipping mem assertions at yama scope {yama_scope}");
        return;
    }
    assert!(
        out.status.success(),
        "script must complete: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("MEM_OPEN_OK"),
        "no arapuca process's mem may be writable by the target: {stdout}"
    );
    assert!(
        stdout.contains("ARAPUCA_PROCS"),
        "must have scanned /proc: {stdout}\nstderr: {stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn uds_policy_serves_reparented_grandchild_connects() {
    // The supervisor is a child subreaper: a target that double-forks
    // leaves grandchildren that re-parent to the supervisor, not to
    // init — keeping them inspectable (and served) on plain Yama-1
    // runs where the supervisor has no CAP_SYS_PTRACE. Without the
    // subreaper, the grandchild's connects fail with EACCES while the
    // wrapper is still alive.
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    // Plain run: the policy needs Yama <= 1 (no user namespace to
    // bypass scope 2 with).
    if std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().parse::<u32>().unwrap_or(0) >= 2)
        .unwrap_or(false)
    {
        eprintln!("skipping: yama ptrace_scope>=2 denies plain-run supervision");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("grandchild.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let served2 = std::sync::Arc::clone(&served);
    let _acceptor = std::thread::spawn(move || {
        for conn in listener.incoming() {
            match conn {
                Ok(c) => {
                    drop(c);
                    served2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(_) => break,
            }
        }
    });
    let script = format!(
        r#"
import os, socket, sys

# Double-fork: the grandchild is re-parented when the intermediate
# exits, ending up under the supervisor (subreaper) instead of init.
pid = os.fork()
if pid == 0:
    pid2 = os.fork()
    if pid2 == 0:
        # Grandchild: WAIT for the intermediate to exit first, so the
        # re-parenting has actually happened before the first connect
        # (otherwise the early connects pass in-tree on any host and
        # the oracle weakens). Then outlive it a little and connect.
        import time
        time.sleep(0.3)
        os.close(0)
        path = {path:?}
        for _ in range(20):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            rc = s.connect_ex(path)
            s.close()
            if rc != 0:
                print("GRANDCHILD_CONNECT_FAILED", rc, flush=True)
                sys.exit(7)
        print("GRANDCHILD_OK", flush=True)
        sys.exit(0)
    os._exit(0)
# Parent (the target): wait for the grandchild indirectly.
os.waitpid(pid, 0)
import time
time.sleep(1.5)
sys.exit(0)
"#,
        path = sock_path.display().to_string()
    );
    // PLAIN run (no --deny-network): with the pid namespace, the
    // grandchild would re-parent to the target itself (pid 1 of its
    // namespace) and stay in the supervisor's tree regardless — only
    // a plain run sends it to host init, which is the case the
    // subreaper exists for.
    let out = Command::new(arapuca_bin())
        .args([
            "run",
            "--seccomp",
            "baseline",
            "--deny-privileged-unix-sockets",
        ])
        .arg("--")
        .arg("/usr/bin/python3")
        .arg("-c")
        .arg(&script)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() || stdout.contains("GRANDCHILD_OK"),
        "grandchild connects must be served after re-parenting: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !stdout.contains("GRANDCHILD_CONNECT_FAILED"),
        "the re-parented grandchild was denied: {stdout}"
    );
    let n = served.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        n >= 20,
        "the grandchild's connects must reach the listener (got {n})"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn uds_policy_availability_follows_yama_scope() {
    // Parent topology: the supervisor inspects its descendant, so
    // plain (no-userns) policy runs are enforced at Yama scopes
    // 0-1 and refused fail-closed at 2+ (scope 2 without caps
    // denies even parent→child; scope 3 denies everything). Both
    // directions are asserted so a regression either way — wrongly
    // refusing a capable host, or running unenforced on a denied
    // one — turns red.
    let scope = yama_scope();
    if scope <= 1 {
        // Capable host: the plain run must SUCCEED (enforced), not
        // be refused. (The child-topology-era oracle inverted this.)
        let out = Command::new(arapuca_bin())
            .args([
                "run",
                "--seccomp",
                "baseline",
                "--deny-privileged-unix-sockets",
                "--",
                "/bin/true",
            ])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(0),
            "plain policy run must be enforced (not refused) at yama scope {scope}: {stderr}"
        );
        return;
    }
    // Scope >= 2: the plain run must be refused fail-closed (the
    // opt-out named), never run unenforced.
    let out = Command::new(arapuca_bin())
        .args([
            "run",
            "--seccomp",
            "baseline",
            "--deny-privileged-unix-sockets",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(125),
        "launch must fail closed: {stderr}"
    );
    assert!(
        stderr.contains("unix socket connect policy"),
        "error must name the policy: {stderr}"
    );
    assert!(
        stderr.contains("--allow-unix-socket-connect"),
        "error must name the opt-out: {stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn uds_policy_survives_signal_interrupted_connects() {
    // ENOENT from SECCOMP_IOCTL_NOTIF_RECV means "notification
    // withdrawn" (the target's blocked syscall was interrupted by a
    // signal handler) as often as it means "filter destroyed". A
    // supervisor that reads it as the latter stops serving while the
    // target lives, and every later connect() blocks forever on a
    // listener nobody reads. This test storms the target with signals
    // while it loops connects under the policy: the run must finish,
    // not hang (the test harness kills it after the deadline and
    // fails it).
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies the supervisor inspection");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("storm.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let served2 = std::sync::Arc::clone(&served);
    let _acceptor = std::thread::spawn(move || {
        // Every connection is dropped immediately: this test measures
        // that connects are served, not that data flows.
        for conn in listener.incoming() {
            match conn {
                Ok(c) => {
                    drop(c);
                    served2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(_) => break,
            }
        }
    });
    let script = format!(
        r#"
import socket, signal, threading, time, sys, os

def handler(signum, frame):
    pass

# No SA_RESTART: an interrupted connect is withdrawn from the
# notification queue, which is what produced the ENOENT.
signal.signal(signal.SIGUSR1, handler)

def storm():
    while True:
        os.kill(os.getpid(), signal.SIGUSR1)
        time.sleep(0.0005)

threading.Thread(target=storm, daemon=True).start()

path = {path:?}
# More connects than the usual 1024 soft NOFILE limit: a supervisor
# that leaks one descriptor per brokered connect hits EMFILE here and
# the remaining connects fail with EACCES.
for _ in range(1500):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    rc = s.connect_ex(path)
    s.close()
    if rc != 0:
        print("CONNECT_FAILED", rc)
        sys.exit(7)
print("STORM_SURVIVED")
"#,
        path = sock_path.display().to_string()
    );
    // Bounded: a regression that wedges the supervisor must fail the
    // test, not hang the suite until the harness kills it.
    let out = run_with_policy_bounded(&["--seccomp", "baseline"], &script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("STORM_SURVIVED"),
        "the supervisor must keep serving across withdrawn notifications: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let n = served.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        n > 0,
        "the storm must have reached the listener at least once (got {n})"
    );
}
#[cfg(target_os = "linux")]
fn run_with_policy_bounded(extra_args: &[&str], target: &str) -> std::process::Output {
    // Same as run_with_policy but (a) under timeout(1): wedged runs
    // fail with 124 instead of hanging the suite, and (b) with the
    // descriptor limit pinned to 1024: hosts with a high default
    // NOFILE would otherwise hide a per-connect supervisor leak until
    // production.
    let mut cmd = std::process::Command::new("timeout");
    cmd.arg("90").arg("bash").arg("-c").arg(format!(
        "ulimit -n 1024; exec {} run --deny-network --seccomp baseline          --deny-privileged-unix-sockets {} -- /usr/bin/python3 -c {}",
        arapuca_bin().display(),
        extra_args.join(" "),
        shell_quote(target)
    ));
    cmd.output().unwrap()
}

#[cfg(target_os = "linux")]
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(target_os = "linux")]
#[test]
fn user_session_sockets_denied_only_when_opted_in() {
    // systemd-run --user through /run/user/<uid>/bus starts a process
    // outside every arapuca layer; by default the policy leaves it
    // reachable (the built-in roots cover root-owned daemons only)
    // and --deny-user-session-sockets opts into denying it.
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies the supervisor inspection");
        return;
    }
    let uid = unsafe { libc::getuid() };
    let bus = format!("/run/user/{uid}/bus");
    // A stand-in listener at the exact path the flag must deny. Only
    // meaningful when the path exists and is bindable by this test
    // (the real bus is usually present on desktop hosts; bind fails
    // with EADDRINUSE then, which skips rather than lies).
    let listener = match std::os::unix::net::UnixListener::bind(&bus) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!("skipping: a real session bus is already bound at {bus}");
            return;
        }
        Err(_) => {
            eprintln!("skipping: {bus} not bindable here");
            return;
        }
    };
    let script = format!(
        r#"
import socket, errno
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
rc = s.connect_ex({bus:?})
print("RC", rc)
assert rc == errno.EACCES, rc
print("SESSION_DENIED")
"#
    );
    let out = run_with_policy(&["--deny-user-session-sockets"], &script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("SESSION_DENIED"),
        "the opt-in flag must deny the session bus: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    drop(listener);

    // Without the flag the same connect must be allowed (the socket
    // is not root-owned and no deny root covers it).
    let listener = std::os::unix::net::UnixListener::bind(&bus).expect("rebind");
    let out = run_with_policy(&[], &script.replace("EACCES", "0"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success() || !stdout.contains("RC 13"),
        "without the opt-in the session bus must stay reachable: {stdout}"
    );
    drop(listener);
}

#[cfg(target_os = "linux")]
#[test]
fn user_session_roots_present_only_when_opted_in() {
    // Unit-level oracle for --deny-user-session-sockets: the CLI test
    // skips on hosts with a live session bus, so the flag's actual
    // effect on the deny roots is pinned here instead.
    let base = arapuca::Profile {
        unix_socket_connect_policy: arapuca::UnixSocketConnectPolicy::DenyPrivileged,
        ..Default::default()
    };
    let (k, v) = arapuca::env::unotify_env(&base).expect("policy active produces config");
    assert_eq!(k, "ARAPUCA_UNOTIFY_CONFIG");
    let uid = unsafe { libc::getuid() };
    let bus = format!("/run/user/{uid}/bus");
    let systemd = format!("/run/user/{uid}/systemd/private");
    assert!(
        !v.contains(&bus),
        "the session bus must stay reachable without the opt-in"
    );
    let opted_in = arapuca::Profile {
        deny_user_session_sockets: true,
        ..base.clone()
    };
    let (_, v2) = arapuca::env::unotify_env(&opted_in).expect("config");
    assert!(
        v2.contains(&bus) && v2.contains(&systemd),
        "the opt-in must add both session roots: {v2}"
    );
}
