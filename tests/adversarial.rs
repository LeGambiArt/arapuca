//! Adversarial security tests for the arapuca binary.
//!
//! These tests verify that the sandbox actually blocks dangerous operations.
//! Each test launches a subprocess through the arapuca binary and verifies
//! that restricted actions fail appropriately.
//!
//! Requires Linux with Landlock (5.13+) and seccomp.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

/// Path to the arapuca binary (built by cargo).
fn arapuca_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove "deps"
    path.push("arapuca");
    path
}

/// Run a command through the arapuca sandbox with given paths.
fn sandboxed_command(
    read_paths: &str,
    write_paths: &str,
    cmd: &str,
    args: &[&str],
) -> std::process::Output {
    Command::new(arapuca_bin())
        .args(["--", cmd])
        .args(args)
        .env("ARAPUCA_WRAPPER", "1")
        // Direct wrapper invocation: declare that no caller extra_fds cross.
        .env("ARAPUCA_TARGET_FDS", "0")
        .env("ARAPUCA_READ_PATHS", read_paths)
        .env("ARAPUCA_WRITE_PATHS", write_paths)
        .output()
        .expect("failed to run arapuca")
}

#[cfg(seccomp_supported)]
fn seccomp_only_command(cmd: &str, args: &[&str]) -> std::process::Output {
    Command::new(arapuca_bin())
        .args(["--", cmd])
        .args(args)
        .env("ARAPUCA_WRAPPER", "1")
        // Direct wrapper invocation: declare that no caller extra_fds cross.
        .env("ARAPUCA_TARGET_FDS", "0")
        .env(
            "ARAPUCA_READ_PATHS",
            "/usr:/lib:/lib64:/bin:/sbin:/etc:/dev:/proc:/tmp",
        )
        .env("ARAPUCA_WRITE_PATHS", "/tmp")
        .output()
        .expect("failed to run arapuca")
}

#[test]
fn landlock_blocks_home_access() {
    // With only /usr, /lib, /bin, /etc, /dev readable, accessing /home should fail.
    let output = sandboxed_command(
        "/usr:/lib:/lib64:/bin:/etc:/dev",
        "/tmp",
        "/bin/cat",
        &["/etc/hostname"], // This should work (in read paths)
    );
    // /etc/hostname should be readable.
    assert!(
        output.status.success(),
        "reading /etc/hostname should succeed"
    );

    // Now try to read something outside allowed paths.
    let output = sandboxed_command(
        "/usr:/lib:/lib64:/bin:/etc:/dev",
        "/tmp",
        "/bin/ls",
        &["/home"],
    );
    assert!(
        !output.status.success(),
        "reading /home should fail under Landlock"
    );
}

#[test]
fn landlock_blocks_write_to_read_path() {
    // /etc is read-only, writing should fail.
    let output = sandboxed_command(
        "/usr:/lib:/lib64:/bin:/etc:/dev:/tmp",
        "/tmp",
        "/bin/sh",
        &["-c", "echo test > /etc/arapuca-test-file 2>&1; echo $?"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The echo should fail with permission denied. The exit code line should not be "0".
    assert!(
        !stdout.trim().ends_with('0')
            || stdout.contains("Permission denied")
            || stdout.contains("Read-only"),
        "writing to read-only path should fail: {stdout}"
    );
}

#[cfg(seccomp_supported)]
#[test]
fn seccomp_blocks_network_ipv4() {
    // Attempt to create an IPv4 socket — should return EPERM.
    let output = seccomp_only_command(
        "/bin/sh",
        &[
            "-c",
            "python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)' 2>&1 || echo 'BLOCKED'",
        ],
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Should either fail with EPERM or the python command should error out.
    assert!(
        combined.contains("BLOCKED")
            || combined.contains("Permission")
            || combined.contains("EPERM")
            || !output.status.success(),
        "IPv4 socket should be blocked: {combined}"
    );
}

#[cfg(seccomp_supported)]
#[test]
fn seccomp_allows_unix_socket() {
    // AF_UNIX sockets should be allowed (needed for JSON-RPC).
    let output = seccomp_only_command(
        "/bin/sh",
        &[
            "-c",
            "python3 -c 'import socket; s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); print(\"OK\")' 2>&1",
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("OK"),
        "AF_UNIX socket should be allowed: {stdout}"
    );
}

#[cfg(seccomp_supported)]
#[test]
fn seccomp_blocks_symlink() {
    // symlink should return EPERM.
    let output = seccomp_only_command(
        "/bin/sh",
        &[
            "-c",
            "ln -s /etc/passwd /tmp/arapuca-test-symlink 2>&1; echo exit=$?",
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Operation not permitted") || stdout.contains("exit=1"),
        "symlink should be blocked: {stdout}"
    );
}

#[cfg(seccomp_supported)]
#[test]
fn seccomp_blocks_ptrace() {
    // ptrace should kill the process.
    let output = seccomp_only_command(
        "/bin/sh",
        &[
            "-c",
            "python3 -c 'import ctypes; ctypes.CDLL(None).ptrace(0,0,0,0)' 2>&1",
        ],
    );
    // The process should be killed (signal 31 = SIGSYS from SECCOMP_RET_KILL_PROCESS)
    // or otherwise fail.
    assert!(
        !output.status.success(),
        "ptrace should cause process termination"
    );
}

#[test]
fn env_stripping() {
    // ARAPUCA_* env vars should be stripped before exec.
    let output = Command::new(arapuca_bin())
        .args(["--", "/bin/sh", "-c", "env | grep ARAPUCA_ || echo CLEAN"])
        .env("ARAPUCA_WRAPPER", "1")
        // Direct wrapper invocation: declare that no caller extra_fds cross.
        .env("ARAPUCA_TARGET_FDS", "0")
        .env("ARAPUCA_READ_PATHS", "/usr:/lib:/lib64:/bin:/etc:/dev")
        .env("ARAPUCA_WRITE_PATHS", "/tmp")
        .env("ARAPUCA_SECRET", "should-not-leak")
        .output()
        .expect("failed to run arapuca");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("CLEAN"),
        "ARAPUCA_* env vars should be stripped: {stdout}"
    );
}

#[test]
fn non_arapuca_env_preserved() {
    // Non-ARAPUCA env vars should be preserved.
    let output = Command::new(arapuca_bin())
        .args(["--", "/bin/sh", "-c", "echo $AGENT_TEST_VAR"])
        .env("ARAPUCA_WRAPPER", "1")
        // Direct wrapper invocation: declare that no caller extra_fds cross.
        .env("ARAPUCA_TARGET_FDS", "0")
        .env("ARAPUCA_READ_PATHS", "/usr:/lib:/lib64:/bin:/etc:/dev")
        .env("ARAPUCA_WRITE_PATHS", "/tmp")
        .env("AGENT_TEST_VAR", "preserved")
        .output()
        .expect("failed to run arapuca");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Note: the arapuca binary clears the environment and only passes
    // through non-ARAPUCA vars from the parent. But it also sets a
    // minimal env. So AGENT_TEST_VAR should be present since the binary
    // filters vars, not clears them.
    assert!(
        stdout.contains("preserved"),
        "non-ARAPUCA env vars should survive: {stdout}"
    );
}
