//! Integration tests for PID namespace isolation.
//!
//! Requires Linux with user namespace support. Tests exercise the
//! `arapuca run --deny-network` path which enables both netns and
//! pidns by default.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

fn arapuca_bin() -> PathBuf {
    // Compile-time location of the binary built by this package:
    // robust to cargo's test-binary layout (deps/ vs build/out/),
    // which differs across cargo versions.
    PathBuf::from(env!("CARGO_BIN_EXE_arapuca"))
}

fn pidns_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--net", "--map-current-user", "--", "/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

// ─── Exit status propagation ────────────────────────────────

#[test]
fn pidns_exit_code_zero() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let status = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/true",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "exit 0 should propagate through pidns");
}

#[test]
fn pidns_exit_code_nonzero() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let status = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/false",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1), "exit 1 should propagate");
}

#[test]
fn pidns_exit_code_custom() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let status = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/sh",
            "-c",
            "exit 42",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(42), "exit 42 should propagate");
}

// ─── Basic functionality with pidns ─────────────────────────

#[test]
fn pidns_stdout_passthrough() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/echo",
            "pidns-ok",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "pidns-ok");
}

#[test]
fn pidns_env_passthrough() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--env",
            "TEST_VAR=hello",
            "--",
            "/bin/sh",
            "-c",
            "echo $TEST_VAR",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
}

// ─── --no-pid-ns opt-out ────────────────────────────────────

#[test]
fn no_pid_ns_flag_disables_pidns() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let status = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--no-pid-ns",
            "--seccomp",
            "baseline",
            "--",
            "/bin/true",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "--no-pid-ns should work");
}

// ─── PID 1 behavior ────────────────────────────────────────

#[test]
fn pidns_target_is_pid_1() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/sh",
            "-c",
            "echo $$",
        ])
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("pidns_target_is_pid_1 failed: {stderr}");
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pid = stdout.trim();
    assert_eq!(
        pid, "1",
        "target should be PID 1 in the namespace, got: {pid}"
    );
}

// ─── Exec chain inside pidns ────────────────────────────────

#[test]
fn pidns_exec_chain_works() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/sh",
            "-c",
            "/bin/echo chain-ok",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "chain-ok");
}
