//! Integration tests for seccomp unotify audit features.
//!
//! These tests verify the `--audit-files` and `--audit-network` CLI
//! flags by launching sandboxed processes via `arapuca run` and
//! checking exit codes and basic behavior.
//!
//! The full audit event pipeline (supervisor → NDJSON → Process::wait
//! → AuditSink) requires the library API with an AuditSink, which is
//! tested separately. These CLI tests verify the wrapper integration
//! path works end-to-end without crashes or hangs.
//!
//! Requires Linux with seccomp_supported (x86_64/aarch64) and
//! kernel >= 5.5 for SECCOMP_USER_NOTIF_FLAG_CONTINUE.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

fn arapuca_bin() -> PathBuf {
    // Compile-time location of the binary built by this package:
    // robust to cargo's test-binary layout (deps/ vs build/out/),
    // which differs across cargo versions.
    PathBuf::from(env!("CARGO_BIN_EXE_arapuca"))
}

fn netns_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--net", "--map-root-user", "--", "/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(seccomp_supported)]
fn unotify_supported() -> bool {
    arapuca::unotify::unotify_available()
}

#[cfg(not(seccomp_supported))]
fn unotify_supported() -> bool {
    false
}

// ─── CLI flag tests ───────────────────────────────────────────

#[test]
fn audit_files_flag_accepted() {
    let output = Command::new(arapuca_bin())
        .args(["run", "--audit-files", "--", "/bin/true"])
        .output()
        .expect("failed to run arapuca");

    // Should succeed regardless of kernel support — the flag is
    // always accepted, unotify is skipped if unavailable.
    assert!(
        output.status.success(),
        "arapuca run --audit-files -- /bin/true should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn audit_network_flag_accepted() {
    let output = Command::new(arapuca_bin())
        .args(["run", "--audit-network", "--", "/bin/true"])
        .output()
        .expect("failed to run arapuca");

    assert!(
        output.status.success(),
        "arapuca run --audit-network -- /bin/true should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn audit_files_and_network_combined() {
    let output = Command::new(arapuca_bin())
        .args(["run", "--audit-files", "--audit-network", "--", "/bin/true"])
        .output()
        .expect("failed to run arapuca");

    assert!(
        output.status.success(),
        "combined flags should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn audit_files_with_cat() {
    if !unotify_supported() {
        eprintln!("skipping: unotify not supported on this kernel");
        return;
    }

    // /etc/hosts is in default read paths and always exists.
    let output = Command::new(arapuca_bin())
        .args(["run", "--audit-files", "--", "/bin/cat", "/etc/hosts"])
        .output()
        .expect("failed to run arapuca");

    assert!(
        output.status.success(),
        "cat /etc/hosts with --audit-files should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.is_empty(), "cat should produce output");
}

#[test]
fn audit_files_with_ls() {
    if !unotify_supported() {
        eprintln!("skipping: unotify not supported on this kernel");
        return;
    }

    // /usr is in default read paths.
    let output = Command::new(arapuca_bin())
        .args(["run", "--audit-files", "--", "/bin/ls", "/usr"])
        .output()
        .expect("failed to run arapuca");

    assert!(
        output.status.success(),
        "ls /usr with --audit-files should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn audit_files_short_lived_process() {
    if !unotify_supported() {
        eprintln!("skipping: unotify not supported on this kernel");
        return;
    }

    // /bin/true exits immediately — tests supervisor cleanup.
    let output = Command::new(arapuca_bin())
        .args(["run", "--audit-files", "--", "/bin/true"])
        .output()
        .expect("failed to run arapuca");

    assert!(
        output.status.success(),
        "/bin/true with --audit-files should exit cleanly, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn deny_network_implies_audit_network() {
    if !netns_available() {
        eprintln!("skipping: netns not available");
        return;
    }
    // --deny-network should implicitly enable network auditing.
    // This test just verifies no crash/hang when both are active.
    let output = Command::new(arapuca_bin())
        .args(["run", "--deny-network", "--", "/bin/true"])
        .output()
        .expect("failed to run arapuca");

    assert!(
        output.status.success(),
        "--deny-network with /bin/true should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn audit_files_with_deny_network() {
    if !netns_available() {
        eprintln!("skipping: netns not available");
        return;
    }
    // Both features active simultaneously.
    let output = Command::new(arapuca_bin())
        .args(["run", "--audit-files", "--deny-network", "--", "/bin/true"])
        .output()
        .expect("failed to run arapuca");

    assert!(
        output.status.success(),
        "combined --audit-files --deny-network should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ─── Graceful degradation ─────────────────────────────────────

#[test]
fn audit_flags_on_unsupported_kernel_degrade_gracefully() {
    // Even if unotify isn't supported, the flags should be accepted
    // and the process should run normally (unotify just skipped).
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--audit-files",
            "--audit-network",
            "--",
            "/bin/echo",
            "hello",
        ])
        .output()
        .expect("failed to run arapuca");

    assert!(
        output.status.success(),
        "should degrade gracefully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello"),
        "echo should still produce output: {stdout}"
    );
}
