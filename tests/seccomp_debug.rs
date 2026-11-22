//! Integration tests for seccomp debug mode (--seccomp-debug).
//!
//! Tests verify that the flag is accepted, doesn't crash, and the
//! sandboxed process runs normally. The SIGSYS handler is only active
//! in internal child processes (bridge, connect proxy, supervisor) and
//! only fires when a blocked syscall is encountered.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

fn arapuca_bin() -> PathBuf {
    // Compile-time location of the binary built by this package:
    // robust to cargo's test-binary layout (deps/ vs build/out/),
    // which differs across cargo versions.
    PathBuf::from(env!("CARGO_BIN_EXE_arapuca"))
}

#[test]
fn seccomp_debug_flag_accepted() {
    let output = Command::new(arapuca_bin())
        .args(["run", "--seccomp-debug", "--", "/bin/true"])
        .output()
        .expect("failed to run arapuca");

    assert!(
        output.status.success(),
        "arapuca run --seccomp-debug -- /bin/true should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn seccomp_debug_with_echo() {
    let output = Command::new(arapuca_bin())
        .args(["run", "--seccomp-debug", "--", "/bin/echo", "hello"])
        .output()
        .expect("failed to run arapuca");

    assert!(
        output.status.success(),
        "should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello"),
        "echo should produce output: {stdout}"
    );
}

#[test]
fn seccomp_debug_combined_with_audit_files() {
    let output = Command::new(arapuca_bin())
        .args(["run", "--seccomp-debug", "--audit-files", "--", "/bin/true"])
        .output()
        .expect("failed to run arapuca");

    assert!(
        output.status.success(),
        "combined flags should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
