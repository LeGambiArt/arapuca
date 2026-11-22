//! Descriptor inheritance oracles.
//!
//! Linux-only: the sweep these oracles exercise is built on
//! close_range(2) and the ARAPUCA_TARGET_FDS contract, neither of
//! which exists on the other platforms (the darwin gap is tracked in
//! staging). macOS additionally caps the default descriptor limit at
//! 256, so even the fd-number arithmetic differs.
#![cfg(target_os = "linux")]
//!
//! The sandbox promises that the target inherits stdio plus whatever
//! the caller listed in `extra_fds`, and nothing else. These tests check
//! both directions: a descriptor the calling process happens to hold
//! must not leak in, and a descriptor the caller asked for must arrive.
//!
//! The negative direction needs its own deterministic probe. The
//! supervisor suite's `inherited_target_fds_are_bounded_*` tests only
//! catch a leak when the tty tests happen to hold a pty master open at
//! the same moment, which is why they pass with the sweep reverted on a
//! serialized run.

use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process::Command;

fn python3_available() -> bool {
    Command::new("python3")
        .arg("-c")
        .arg("pass")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn arapuca_bin() -> PathBuf {
    // Compile-time location of the binary built by this package:
    // robust to cargo's test-binary layout (deps/ vs build/out/),
    // which differs across cargo versions.
    PathBuf::from(env!("CARGO_BIN_EXE_arapuca"))
}

fn config(dir: &std::path::Path) -> arapuca::Config {
    arapuca::Config {
        profile: arapuca::Profile {
            // /proc so the probe can list its own descriptors, /dev for
            // the python runtime.
            read_paths: vec![
                "/usr".into(),
                "/lib".into(),
                "/lib64".into(),
                "/bin".into(),
                "/etc".into(),
                "/dev".into(),
                "/proc".into(),
            ],
            write_paths: vec![dir.to_path_buf()],
            allow_exec: true,
            ..Default::default()
        },
        socket_dir: PathBuf::new(),
        task_id: format!("fd-inherit-{}", std::process::id()),
        phase: "test".into(),
        work_dir: None,
        stdin: None,
        stdout: None,
        stderr: None,
        extra_fds: vec![],
        tty: false,
        network_proxy_socket: None,
        #[cfg(target_os = "linux")]
        allowed_hosts: vec![],
        env: vec![],
        audit_sink: None,
        audit_verbosity: Default::default(),
        audit_principal: None,
        audit_correlation_id: None,
    }
}

/// Duplicate `fd` onto the lowest free descriptor `>= min`.
///
/// Never target a fixed number: `dup2` onto an occupied descriptor
/// closes it, and this process is shared with the rest of the suite.
fn dup_at_least(fd: i32, min: i32) -> i32 {
    // SAFETY: F_DUPFD with a valid descriptor. No CLOEXEC, which is the
    // point: the duplicate is exactly the kind of descriptor the sweep
    // has to catch.
    let out = unsafe { libc::fcntl(fd, libc::F_DUPFD, min) };
    assert!(out >= min, "F_DUPFD({min}) -> {out}");
    out
}

fn launch_probe(cfg: &arapuca::Config, script: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let stdout = std::fs::File::create(dir.path().join("out")).unwrap();
    let stderr = std::fs::File::create(dir.path().join("err")).unwrap();
    let mut cfg = cfg.clone();
    cfg.stdout = Some(stdout.as_raw_fd());
    cfg.stderr = Some(stderr.as_raw_fd());
    use arapuca::platform::Sandbox;
    let mut process = arapuca::platform::new()
        .unwrap()
        .launch(&cfg, "/usr/bin/python3", &["-c", script])
        .unwrap();
    let status = process.wait().unwrap();
    let out = std::fs::read_to_string(dir.path().join("out")).unwrap_or_default();
    assert!(
        status.success(),
        "probe must run: {out}\n{}",
        std::fs::read_to_string(dir.path().join("err")).unwrap_or_default()
    );
    out
}

#[test]
fn a_descriptor_the_caller_holds_does_not_reach_the_target() {
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // A plain file: the content is beside the point, the descriptor is
    // what must not cross.
    let file = std::fs::File::create(dir.path().join("secret")).unwrap();
    let planted = dup_at_least(file.as_raw_fd(), 40);

    let cfg = config(dir.path());
    let out = launch_probe(
        &cfg,
        &format!(
            r#"
import os
fds = sorted(int(f) for f in os.listdir('/proc/self/fd'))
print('FDS', fds)
try:
    os.read({planted}, 1)
except OSError:
    print('NOT_READABLE')
else:
    print('READ')
"#
        ),
    );
    // SAFETY: closing a descriptor this test owns.
    unsafe { libc::close(planted) };

    assert!(
        !out.lines().any(|l| l.starts_with("READ")),
        "the target read a descriptor the caller never handed over: {out}"
    );
    let fds: Vec<i32> = out
        .lines()
        .find_map(|l| l.strip_prefix("FDS "))
        .map(|v| {
            v.trim_matches(|c| c == '[' || c == ']')
                .replace(',', " ")
                .split_whitespace()
                .filter_map(|n| n.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        fds.iter().all(|fd| *fd <= 3),
        "target inherited descriptors beyond stdio: {fds:?} ({out})"
    );
}

#[test]
fn a_descriptor_the_caller_asked_for_reaches_the_target() {
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payload");
    std::fs::write(&path, b"delivered").unwrap();
    let file = std::fs::File::open(&path).unwrap();

    let mut cfg = config(dir.path());
    // Remapped to fd 3 by the launcher, so the target reads it there.
    cfg.extra_fds = vec![file.as_raw_fd()];
    let out = launch_probe(
        &cfg,
        r#"
import os
print('DATA', os.read(3, 32))
"#,
    );

    assert!(
        out.contains("DATA b'delivered'"),
        "the requested descriptor did not reach the target: {out}"
    );
}

#[test]
fn a_requested_descriptor_above_1024_reaches_the_target() {
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payload");
    std::fs::write(&path, b"highfd").unwrap();
    let file = std::fs::File::open(&path).unwrap();
    // The old sweep ceiling was 1024; a caller descriptor above it has to
    // survive the sweep or the fix would silently drop it.
    let high = dup_at_least(file.as_raw_fd(), 1500);

    let mut cfg = config(dir.path());
    cfg.extra_fds = vec![high];
    let out = launch_probe(
        &cfg,
        r#"
import os
print('DATA', os.read(3, 32))
"#,
    );
    // SAFETY: closing a descriptor this test owns.
    unsafe { libc::close(high) };

    assert!(
        out.contains("DATA b'highfd'"),
        "a descriptor above 1024 did not reach the target: {out}"
    );
}

fn run_wrapper(extra_env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(arapuca_bin());
    cmd.args(["--", "/bin/echo", "TARGET_EXECUTED"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("ARAPUCA_WRAPPER", "1")
        .env("ARAPUCA_READ_PATHS", "/usr:/lib:/lib64:/bin:/etc")
        .env("ARAPUCA_WRITE_PATHS", "/tmp");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("run wrapper")
}

#[test]
fn a_wrapper_without_the_descriptor_contract_fails_closed() {
    let out = run_wrapper(&[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "the wrapper must refuse to run without the contract: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("TARGET_EXECUTED"),
        "the target ran without the descriptor contract in place"
    );
    assert!(
        stderr.contains("ARAPUCA_TARGET_FDS"),
        "the failure must name the missing contract: {stderr}"
    );
}

#[test]
fn a_malformed_descriptor_contract_fails_closed() {
    // 17 is above the extra_fds ceiling; a value the launcher could never
    // legitimately send.
    let out = run_wrapper(&[("ARAPUCA_TARGET_FDS", "17")]);
    assert!(
        !out.status.success(),
        "an out-of-range descriptor count must be rejected"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("TARGET_EXECUTED"),
        "the target ran with a malformed descriptor contract"
    );
}
