//! CLI dispatch hardening tests.
//!
//! Verifies that unrecognized arguments at args[1] are rejected
//! before reaching the internal wrapper path. These tests are
//! platform-independent — the dispatch guard runs before any
//! OS-specific sandbox code.

use std::path::PathBuf;
use std::process::Command;

fn arapuca_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove "deps"
    path.push("arapuca");
    path
}

// ─── Security property tests ──────────────────────────────────
//
// These verify the command did NOT execute — not just the exit code.

#[test]
fn reported_bypass_does_not_execute() {
    let dir = tempfile::Builder::new()
        .prefix("arapuca-bypass-")
        .tempdir()
        .unwrap();
    let victim = dir.path().join("victim-file");
    std::fs::write(&victim, "must survive").unwrap();

    let _status = Command::new(arapuca_bin())
        .args(["-h", "run", "--", "/bin/rm"])
        .arg(&victim)
        .output()
        .unwrap();

    assert!(
        victim.exists(),
        "file must not be deleted — the reported bypass vector must be blocked"
    );
}

#[test]
fn unknown_flag_does_not_execute() {
    let dir = tempfile::Builder::new()
        .prefix("arapuca-bypass-")
        .tempdir()
        .unwrap();
    let marker = dir.path().join("should-not-exist");

    let _status = Command::new(arapuca_bin())
        .args(["--bogus", "run", "--", "/bin/touch"])
        .arg(&marker)
        .output()
        .unwrap();

    assert!(
        !marker.exists(),
        "command must not execute with unknown flag at args[1]"
    );
}

// ─── Dispatch rejection tests ─────────────────────────────────

#[test]
fn flag_h_before_subcommand_rejected() {
    let output = Command::new(arapuca_bin())
        .args(["-h", "run", "--", "/bin/true"])
        .output()
        .unwrap();
    // -h shows help (exit 0) but does NOT execute the command.
    // The security property test above verifies no execution.
    assert!(output.status.success(), "-h should show help and exit 0");
}

#[test]
fn bogus_flag_rejected() {
    let output = Command::new(arapuca_bin())
        .args(["--bogus", "--", "/bin/true"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown flag"),
        "should say unknown flag: {stderr}"
    );
}

#[test]
fn deny_network_with_allow_network_listeners_rejected() {
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--allow-network-listeners",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--deny-network and --allow-network-listeners are mutually exclusive"),
        "should reject combination, got: {stderr}"
    );
}

#[test]
fn unknown_subcommand_rejected() {
    let output = Command::new(arapuca_bin())
        .args(["foo", "--", "/bin/true"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown subcommand"),
        "should say unknown subcommand: {stderr}"
    );
}

#[test]
fn empty_string_arg1_rejected() {
    let output = Command::new(arapuca_bin())
        .args(["", "--", "/bin/true"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn flag_before_subcommand_rejected() {
    let output = Command::new(arapuca_bin())
        .args(["-v", "/tmp", "run", "--", "/bin/true"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

// ─── Help and version ─────────────────────────────────────────

#[test]
fn help_short_flag() {
    let output = Command::new(arapuca_bin()).args(["-h"]).output().unwrap();
    assert!(output.status.success(), "-h should exit 0");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage:"), "should print usage: {stderr}");
}

#[test]
fn help_long_flag() {
    let output = Command::new(arapuca_bin())
        .args(["--help"])
        .output()
        .unwrap();
    assert!(output.status.success(), "--help should exit 0");
}

#[test]
fn version_short_flag() {
    let output = Command::new(arapuca_bin()).args(["-V"]).output().unwrap();
    assert!(output.status.success(), "-V should exit 0");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("arapuca"), "should print version: {stderr}");
}

#[test]
fn version_long_flag() {
    let output = Command::new(arapuca_bin())
        .args(["--version"])
        .output()
        .unwrap();
    assert!(output.status.success(), "--version should exit 0");
}

// ─── Edge cases ───────────────────────────────────────────────

#[test]
fn no_args_shows_usage() {
    let output = Command::new(arapuca_bin()).output().unwrap();
    assert!(!output.status.success(), "no args should exit non-zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage:"), "should print usage: {stderr}");
}

#[test]
fn separator_only_no_command() {
    let output = Command::new(arapuca_bin()).args(["--"]).output().unwrap();
    assert!(
        !output.status.success(),
        "-- with no command should exit non-zero"
    );
}

// ─── Wrapper sentinel tests ──────────────────────────────────

#[test]
fn wrapper_without_sentinel_does_not_execute() {
    let dir = tempfile::Builder::new()
        .prefix("arapuca-wrapper-")
        .tempdir()
        .unwrap();
    let marker = dir.path().join("should-not-exist");

    let _status = Command::new(arapuca_bin())
        .args(["--", "/bin/touch"])
        .arg(&marker)
        .output()
        .unwrap();

    assert!(
        !marker.exists(),
        "wrapper path without ARAPUCA_WRAPPER must not execute"
    );
}

#[test]
fn wrapper_without_sentinel_exits_nonzero() {
    let output = Command::new(arapuca_bin())
        .args(["--", "/bin/true"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "wrapper without sentinel should exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ARAPUCA_WRAPPER"),
        "should mention ARAPUCA_WRAPPER: {stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn wrapper_with_sentinel_and_paths_succeeds() {
    let output = Command::new(arapuca_bin())
        .args(["--", "/bin/true"])
        .env("ARAPUCA_WRAPPER", "1")
        .env("ARAPUCA_READ_PATHS", "/usr:/lib:/lib64:/bin")
        .env("ARAPUCA_WRITE_PATHS", "/tmp")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "wrapper with sentinel + paths should succeed"
    );
}
