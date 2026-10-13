//! Unix socket denial's executable, descriptor and direct-apply boundaries.
#![cfg(all(target_os = "linux", seccomp_supported))]

use arapuca::platform::Sandbox;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_arapuca"))
}

fn config() -> arapuca::Config {
    let (read_paths, write_paths) = arapuca::env::default_sandbox_paths();
    arapuca::Config {
        profile: arapuca::Profile {
            read_paths,
            write_paths,
            allow_exec: true,
            deny_unix_sockets: true,
            ..Default::default()
        },
        socket_dir: PathBuf::new(),
        task_id: format!("unix-policy-{}", std::process::id()),
        phase: "test".into(),
        work_dir: None,
        stdin: None,
        stdout: None,
        stderr: None,
        extra_fds: vec![],
        tty: false,
        network_proxy_socket: None,
        allowed_hosts: vec![],
        env: vec![],
        audit_sink: None,
        audit_verbosity: Default::default(),
        audit_principal: None,
        audit_correlation_id: None,
    }
}

fn wait_bounded(process: &mut arapuca::Process) -> std::process::ExitStatus {
    let pid = process.pid();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watch = done.clone();
    let watchdog = std::thread::spawn(move || {
        for _ in 0..1000 {
            if watch.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    });
    let status = process.wait().unwrap();
    done.store(true, std::sync::atomic::Ordering::Release);
    watchdog.join().unwrap();
    status
}

const SOCKET_PROBE: &str = "import socket,errno,fcntl\nfor ty in (socket.SOCK_STREAM,socket.SOCK_DGRAM):\n for op in (lambda:socket.socket(socket.AF_UNIX,ty),lambda:socket.socketpair(socket.AF_UNIX,ty)):\n  try: op()\n  except OSError as e: assert e.errno==errno.EPERM,e\n  else: raise AssertionError('Unix socket unexpectedly allowed')\nfor fd in range(3,128):\n try: fcntl.fcntl(fd,fcntl.F_GETFD)\n except OSError as e: assert e.errno==errno.EBADF,e\n else: raise AssertionError('Bootstrap fd retained: '+str(fd))\nprint('UNIX_DENIED')";

#[test]
fn cli_denial_is_enforced_in_both_profiles() {
    for mode in ["strict", "baseline"] {
        let out = Command::new(binary())
            .args([
                "run",
                "--no-unix-sockets",
                "--seccomp",
                mode,
                "--",
                "/usr/bin/python3",
                "-c",
                SOCKET_PROBE,
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("UNIX_DENIED"));
    }
}

#[test]
fn default_off_retains_unix_socket_compatibility() {
    let out = Command::new(binary())
        .args([
            "run",
            "--",
            "/usr/bin/python3",
            "-c",
            "import socket; s=socket.socket(socket.AF_UNIX); print('UNIX_ALLOWED')",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("UNIX_ALLOWED"));
}

#[test]
fn malformed_policy_transport_prevents_execution() {
    let out = Command::new(binary())
        .args(["--", "/bin/echo", "TARGET_EXECUTED"])
        .env("ARAPUCA_WRAPPER", "1")
        .env("ARAPUCA_DENY_UNIX_SOCKETS", "bad")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("TARGET_EXECUTED"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid ARAPUCA_DENY_UNIX_SOCKETS"));
}

#[test]
fn pipe_io_survives_enabled_policy() {
    let mut child = Command::new(binary())
        .args(["run", "--no-unix-sockets", "--", "/bin/cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(b"PIPE_OK\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, b"PIPE_OK\n");
}

#[test]
fn pty_io_survives_enabled_policy() {
    let mut cfg = config();
    cfg.tty = true;
    let mut process = arapuca::platform::new()
        .unwrap()
        .launch(&cfg, "/bin/echo", &["PTY_OK"])
        .unwrap();
    let master = process.pty_master().unwrap().as_raw_fd();
    assert!(wait_bounded(&mut process).success());
    let mut buf = [0u8; 64];
    let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
    assert!(n > 0, "{}", std::io::Error::last_os_error());
    assert!(String::from_utf8_lossy(&buf[..n as usize]).contains("PTY_OK"));
    process.cleanup();
}

#[test]
fn retained_connected_extra_fd_prevents_target_execution() {
    let dir = tempfile::tempdir().unwrap();
    let stdout = File::create(dir.path().join("stdout")).unwrap();
    let stderr = File::create(dir.path().join("stderr")).unwrap();
    let (socket, _peer) = UnixStream::pair().unwrap();
    let mut cfg = config();
    cfg.stdout = Some(stdout.as_raw_fd());
    cfg.stderr = Some(stderr.as_raw_fd());
    cfg.extra_fds = vec![socket.as_raw_fd()];
    let mut process = arapuca::platform::new()
        .unwrap()
        .launch(&cfg, "/bin/echo", &["TARGET_EXECUTED"])
        .unwrap();
    let status = wait_bounded(&mut process);
    assert!(!status.success());
    assert!(
        !std::fs::read_to_string(dir.path().join("stdout"))
            .unwrap()
            .contains("TARGET_EXECUTED")
    );
    assert!(
        std::fs::read_to_string(dir.path().join("stderr"))
            .unwrap()
            .contains("AF_UNIX")
    );
}

// A glibc init-array fixture exercises the same pre-runtime argc/argv entry
// contract as the C constructor used by selfexec consumers.
#[cfg(target_env = "gnu")]
unsafe extern "C" fn constructor(
    argc: libc::c_int,
    argv: *const *const libc::c_char,
    _env: *const *const libc::c_char,
) {
    if argc >= 2 {
        let wrapper = unsafe { libc::getenv(c"ARAPUCA_WRAPPER".as_ptr()) };
        if !wrapper.is_null()
            && unsafe { libc::strcmp(wrapper, c"1".as_ptr()) } == 0
            && unsafe { libc::strcmp(*argv.add(1), c"--".as_ptr()) } == 0
        {
            arapuca::selfexec::arapuca_handle_selfexec_if_wrapper(argc, argv);
        }
    }
}

#[cfg(target_env = "gnu")]
#[used]
#[unsafe(link_section = ".init_array")]
static SELFEXEC_CONSTRUCTOR: unsafe extern "C" fn(
    libc::c_int,
    *const *const libc::c_char,
    *const *const libc::c_char,
) = constructor;

#[test]
#[cfg(target_env = "gnu")]
fn selfexec_constructor_enforces_policy() {
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--", "/usr/bin/python3", "-c", SOCKET_PROBE])
        .env("ARAPUCA_WRAPPER", "1")
        .env("ARAPUCA_DENY_UNIX_SOCKETS", "1")
        .env("ARAPUCA_ALLOW_EXEC", "1")
        .env("ARAPUCA_READ_PATHS", "/usr:/lib:/lib64:/bin:/etc")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("UNIX_DENIED"));
}

#[test]
fn direct_apply_fixture() {
    if std::env::var("UNIX_POLICY_FFI_FIXTURE").as_deref() != Ok("1") {
        return;
    }
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let (_socket, _peer) = UnixStream::pair().unwrap();
        let profile = arapuca::ffi::arapuca_profile_new();
        unsafe {
            arapuca::ffi::arapuca_profile_set_deny_unix_sockets(profile, true);
        }
        let before = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        let result = unsafe { arapuca::ffi::arapuca_apply(profile) };
        let error_ptr = arapuca::ffi::arapuca_last_error();
        if result != -1 || error_ptr.is_null() {
            unsafe { libc::_exit(1) };
        }
        let error = unsafe { std::ffi::CStr::from_ptr(error_ptr) };
        if result == -1
            && error.to_bytes().windows(7).any(|v| v == b"AF_UNIX")
            && unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == before
        {
            unsafe { libc::_exit(42) };
        }
        unsafe { libc::_exit(1) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 42);
    println!("FFI_REJECTED_BEFORE_RESTRICTIONS");
}

#[test]
fn direct_apply_rejection_precedes_irreversible_restrictions() {
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "direct_apply_fixture", "--nocapture"])
        .env("UNIX_POLICY_FFI_FIXTURE", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("FFI_REJECTED_BEFORE_RESTRICTIONS"));
}

#[cfg(feature = "serde")]
struct Events(std::sync::Mutex<Vec<arapuca::audit::AuditEvent>>);
#[cfg(feature = "serde")]
impl arapuca::audit::AuditSink for Events {
    fn emit(&self, event: arapuca::audit::AuditEvent) {
        self.0.lock().unwrap().push(event);
    }
}

#[test]
#[cfg(feature = "serde")]
fn enabled_policy_keeps_unotify_and_pid_namespace_functional() {
    if !Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--pid",
            "--fork",
            "--",
            "/bin/true",
        ])
        .status()
        .is_ok_and(|s| s.success())
    {
        eprintln!(
            "SKIP: user/PID namespaces unavailable; enabled-policy unotify remains unverified"
        );
        return;
    }
    let sink = std::sync::Arc::new(Events(std::sync::Mutex::new(vec![])));
    let mut cfg = config();
    cfg.profile.use_pidns = true;
    cfg.profile.audit_file_access = true;
    cfg.audit_sink = Some(sink.clone());
    let mut process = arapuca::platform::new()
        .unwrap()
        .launch(&cfg, "/usr/bin/python3", &["-c", SOCKET_PROBE])
        .unwrap();
    assert!(wait_bounded(&mut process).success());
    process.cleanup();
    let events = sink.0.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, arapuca::audit::AuditEvent::FileAccess { .. })),
        "no observed FileAccess event"
    );
    assert!(events.iter().any(|e| matches!(
        e,
        arapuca::audit::AuditEvent::SeccompPolicy {
            deny_unix_sockets: true,
            ..
        }
    )));
}

#[test]
#[cfg(all(feature = "serde", target_env = "gnu"))]
fn selfexec_constructor_keeps_unotify_and_pid_namespace_functional() {
    use std::os::unix::process::CommandExt;
    if !Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--pid",
            "--fork",
            "--",
            "/bin/true",
        ])
        .status()
        .is_ok_and(|s| s.success())
    {
        eprintln!("SKIP: user/PID namespaces unavailable; selfexec unotify remains unverified");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let audit = File::create(dir.path().join("audit")).unwrap();
    let fd = audit.as_raw_fd();
    let mut command = Command::new("unshare");
    command
        .args(["--user", "--map-root-user", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--", "/usr/bin/python3", "-c", SOCKET_PROBE])
        .env("ARAPUCA_WRAPPER", "1")
        .env("ARAPUCA_DENY_UNIX_SOCKETS", "1")
        .env("ARAPUCA_ALLOW_EXEC", "1")
        .env("ARAPUCA_READ_PATHS", "/usr:/lib:/lib64:/bin:/etc:/proc")
        .env("ARAPUCA_PID_NS", "1")
        .env("ARAPUCA_UNOTIFY_CONFIG", "file")
        .env("ARAPUCA_UNOTIFY_AUDIT_FD", fd.to_string());
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("UNIX_DENIED"));
    let events = std::fs::read_to_string(dir.path().join("audit")).unwrap();
    assert!(
        events.lines().any(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["type"] == "file_access"
        }),
        "no observed file-access notification: {events}"
    );
}

#[test]
fn enabled_policy_keeps_the_delegated_tcp_to_unix_bridge_functional() {
    if !Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--", "/bin/true"])
        .status()
        .is_ok_and(|s| s.success())
    {
        eprintln!("SKIP: network namespace unavailable; enabled-policy bridge remains unverified");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("echo.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let echo = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut buf = [0; 7];
                    stream.read_exact(&mut buf).unwrap();
                    stream.write_all(&buf).unwrap();
                    return;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("{e}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "bridge never connected"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });
    let mut cfg = config();
    cfg.profile.use_netns = true;
    cfg.profile.seccomp_profile = arapuca::SeccompProfile::Baseline;
    cfg.profile.write_paths.push(dir.path().to_path_buf());
    cfg.network_proxy_socket = Some(path);
    let script = format!(
        "{SOCKET_PROBE}\ns=socket.create_connection(('127.0.0.1',18080),timeout=5); s.sendall(b'RELAYOK'); assert s.recv(7)==b'RELAYOK'"
    );
    let mut process = arapuca::platform::new()
        .unwrap()
        .launch(&cfg, "/usr/bin/python3", &["-c", &script])
        .unwrap();
    assert!(wait_bounded(&mut process).success());
    process.cleanup();
    echo.join().unwrap();
}

#[test]
#[cfg(target_env = "gnu")]
fn selfexec_constructor_keeps_the_delegated_bridge_functional() {
    use std::io::{Read, Write};
    if !Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--", "/bin/true"])
        .status()
        .is_ok_and(|s| s.success())
    {
        eprintln!("SKIP: network namespace unavailable; selfexec bridge remains unverified");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("echo.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let echo = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut buf = [0; 7];
                    stream.read_exact(&mut buf).unwrap();
                    stream.write_all(&buf).unwrap();
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("{e}"),
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });
    let script = format!(
        "{SOCKET_PROBE}\ns=socket.create_connection(('127.0.0.1',18080),timeout=5); s.sendall(b'RELAYOK'); assert s.recv(7)==b'RELAYOK'"
    );
    let out = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--", "/usr/bin/python3", "-c", &script])
        .env("ARAPUCA_WRAPPER", "1")
        .env("ARAPUCA_DENY_UNIX_SOCKETS", "1")
        .env("ARAPUCA_ALLOW_EXEC", "1")
        .env("ARAPUCA_READ_PATHS", "/usr:/lib:/lib64:/bin:/etc")
        .env("ARAPUCA_WRITE_PATHS", dir.path())
        .env("ARAPUCA_SECCOMP_PROFILE", "baseline")
        .env("ARAPUCA_PROXY_BRIDGE", format!("18080:{}", path.display()))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("UNIX_DENIED"));
    echo.join().unwrap();
}

#[test]
fn retained_sqpoll_ring_with_hidden_unix_socket_is_rejected() {
    use std::io::Read;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicU32, Ordering};
    // Stable io_uring_params UAPI: ten u32 fields then two 40-byte offsets.
    let mut params = [0u32; 30];
    params[2] = 2; // IORING_SETUP_SQPOLL
    params[4] = 30_000; // Keep the polling worker awake through the control.
    let raw = unsafe { libc::syscall(libc::SYS_io_uring_setup, 2u32, params.as_mut_ptr()) };
    if raw < 0 {
        let e = std::io::Error::last_os_error();
        assert!(
            matches!(
                e.raw_os_error(),
                Some(libc::EPERM | libc::ENOSYS | libc::EOPNOTSUPP)
            ),
            "{e}"
        );
        eprintln!(
            "SKIP: SQPOLL setup unavailable ({e}); inherited-ring runtime control remains unverified"
        );
        return;
    }
    let ring = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let (socket, mut peer) = UnixStream::pair().unwrap();
    let fixed_fd = socket.as_raw_fd();
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                ring.as_raw_fd(),
                2u32,
                &fixed_fd,
                1u32,
            )
        },
        0
    );
    let message = b"RING_OK".to_vec();
    let buffer = libc::iovec {
        iov_base: message.as_ptr().cast_mut().cast(),
        iov_len: message.len(),
    };
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                ring.as_raw_fd(),
                0u32,
                &buffer,
                1u32,
            )
        },
        0
    );
    drop(socket); // The registered endpoint is now invisible in /proc/self/fd.

    struct Mapping(*mut u8, usize);
    impl Drop for Mapping {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(self.0.cast(), self.1);
            }
        }
    }
    fn map(fd: i32, len: usize, offset: libc::off_t) -> Mapping {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                offset,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        Mapping(ptr.cast(), len)
    }
    let sq_len = params[16] as usize + params[0] as usize * 4;
    let cq_len = params[25] as usize + params[1] as usize * 16;
    let sq = map(
        ring.as_raw_fd(),
        if params[5] & 1 != 0 {
            sq_len.max(cq_len)
        } else {
            sq_len
        },
        0,
    );
    let sqes = map(ring.as_raw_fd(), params[0] as usize * 64, 0x1000_0000);
    let cq = map(ring.as_raw_fd(), cq_len, 0x0800_0000);
    let flags = unsafe { &*sq.0.add(params[14] as usize).cast::<AtomicU32>() };
    if flags.load(Ordering::Acquire) & 1 != 0 {
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_io_uring_enter,
                    ring.as_raw_fd(),
                    0u32,
                    0u32,
                    2u32,
                    std::ptr::null::<u8>(),
                    0usize,
                )
            },
            0
        );
    }
    // WRITE_FIXED (opcode 5), IOSQE_FIXED_FILE (flag 1), fixed file index 0,
    // registered buffer index 0. Publish only after all SQE fields are ready.
    unsafe {
        std::ptr::write_bytes(sqes.0, 0, 64);
        *sqes.0 = 5;
        *sqes.0.add(1) = 1;
        std::ptr::write_unaligned(sqes.0.add(8).cast::<u64>(), u64::MAX);
        std::ptr::write_unaligned(sqes.0.add(16).cast::<u64>(), message.as_ptr() as u64);
        std::ptr::write_unaligned(sqes.0.add(24).cast::<u32>(), message.len() as u32);
        let tail = &*sq.0.add(params[11] as usize).cast::<AtomicU32>();
        let index = tail.load(Ordering::Relaxed);
        let mask = std::ptr::read_volatile(sq.0.add(params[12] as usize).cast::<u32>());
        std::ptr::write_volatile(
            sq.0.add(params[16] as usize)
                .cast::<u32>()
                .add((index & mask) as usize),
            0,
        );
        tail.store(index.wrapping_add(1), Ordering::Release);
    }
    peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut received = [0; 7];
    peer.read_exact(&mut received).unwrap_or_else(|e| {
        let tail = unsafe { &*cq.0.add(params[21] as usize).cast::<AtomicU32>() }.load(Ordering::Acquire);
        let result = unsafe { std::ptr::read_volatile(cq.0.add(params[25] as usize + 8).cast::<i32>()) };
        let sq_head = unsafe { &*sq.0.add(params[10] as usize).cast::<AtomicU32>() }.load(Ordering::Acquire);
        let sq_tail = unsafe { &*sq.0.add(params[11] as usize).cast::<AtomicU32>() }.load(Ordering::Acquire);
        panic!("SQPOLL control: {e}; CQ tail={tail}, result={result}, SQ head={sq_head}, tail={sq_tail}, flags={}, params={params:?}", flags.load(Ordering::Acquire));
    });
    assert_eq!(
        &received[..],
        message.as_slice(),
        "SQPOLL off-policy control did not perform socket I/O"
    );

    let dir = tempfile::tempdir().unwrap();
    let stdout = File::create(dir.path().join("stdout")).unwrap();
    let stderr = File::create(dir.path().join("stderr")).unwrap();
    let mut cfg = config();
    cfg.stdout = Some(stdout.as_raw_fd());
    cfg.stderr = Some(stderr.as_raw_fd());
    cfg.extra_fds = vec![ring.as_raw_fd()];
    for profile in [
        arapuca::SeccompProfile::Strict,
        arapuca::SeccompProfile::Baseline,
    ] {
        cfg.profile.seccomp_profile = profile;
        let mut process = arapuca::platform::new()
            .unwrap()
            .launch(&cfg, "/bin/echo", &["TARGET_EXECUTED"])
            .unwrap();
        assert!(!wait_bounded(&mut process).success());
        process.cleanup();
    }
    assert!(
        !std::fs::read_to_string(dir.path().join("stdout"))
            .unwrap()
            .contains("TARGET_EXECUTED")
    );
    assert!(
        std::fs::read_to_string(dir.path().join("stderr"))
            .unwrap()
            .contains("io_uring ring")
    );
}

struct DiscardEvents;
impl arapuca::audit::AuditSink for DiscardEvents {
    fn emit(&self, _event: arapuca::audit::AuditEvent) {}
}

#[test]
fn wrapper_compatibility_fixture() {
    let Ok(kind) = std::env::var("UNIX_POLICY_WRAPPER_FIXTURE") else {
        return;
    };
    let dir = PathBuf::from(std::env::var_os("UNIX_POLICY_WRAPPER_DIR").unwrap());
    for audit in [false, true] {
        if kind == "advertises_without_enforcing" && audit {
            continue;
        }
        let stdout = File::create(dir.join("stdout")).unwrap();
        let stderr = File::create(dir.join("stderr")).unwrap();
        let mut cfg = config();
        cfg.stdout = Some(stdout.as_raw_fd());
        cfg.stderr = Some(stderr.as_raw_fd());
        if audit {
            cfg.audit_sink = Some(std::sync::Arc::new(DiscardEvents));
        }
        let result = arapuca::platform::new().unwrap().launch(
            &cfg,
            "/usr/bin/python3",
            &["-c", SOCKET_PROBE],
        );
        if kind == "legacy" {
            assert!(result.is_err());
            assert!(std::fs::read(dir.join("stdout")).unwrap().is_empty());
        } else {
            // A trusted wrapper that lies about enforcement defeats the
            // contract oracle: advertisement itself does not sandbox a task.
            let mut process = result.unwrap();
            assert!(!wait_bounded(&mut process).success());
            assert!(
                std::fs::read_to_string(dir.join("stderr"))
                    .unwrap()
                    .contains("Unix socket unexpectedly allowed")
            );
        }
    }
    println!("WRAPPER_CONTRACT_CHECKED");
}

#[test]
fn compatibility_gate_and_enforcement_oracle_cover_version_skew() {
    use std::os::unix::fs::PermissionsExt;
    for kind in ["legacy", "advertises_without_enforcing"] {
        let dir = tempfile::tempdir().unwrap();
        let consumer = dir.path().join("consumer");
        std::fs::copy(std::env::current_exe().unwrap(), &consumer).unwrap();
        let wrapper = dir.path().join("arapuca");
        let response = if kind == "legacy" {
            "exit 1"
        } else {
            "printf 'arapuca unix-socket-denial-v1\\n'; exit 0"
        };
        std::fs::write(&wrapper, format!("#!/bin/sh\nif [ \"$1\" = --wrapper-capabilities ]; then {response}; fi\nshift\nexec \"$@\"\n")).unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        let out = Command::new(&consumer)
            .args(["--exact", "wrapper_compatibility_fixture", "--nocapture"])
            .env("UNIX_POLICY_WRAPPER_FIXTURE", kind)
            .env("UNIX_POLICY_WRAPPER_DIR", dir.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("WRAPPER_CONTRACT_CHECKED"));
    }
}
