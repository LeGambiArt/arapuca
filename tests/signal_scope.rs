//! Integration tests for Landlock signal scoping (`Scope::Signal`):
//! with the scope active, a signal from inside the sandbox to a
//! process outside its Landlock domain must fail with EPERM.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

fn arapuca_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_arapuca"))
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

fn run_target(extra_args: &[&str], script: &str, target_pid: u32) -> std::process::Output {
    let mut cmd = Command::new(arapuca_bin());
    cmd.args(["run"])
        .args(extra_args)
        .arg("--")
        .arg("/usr/bin/python3")
        .arg("-c")
        .arg(script)
        .arg(target_pid.to_string());
    cmd.output().unwrap()
}

/// Strict (the default) locks signal scoping on; Baseline leaves it
/// off. The Baseline run is the discriminating control: without it,
/// a scope that never engaged would also "pass" the EPERM assertion.
#[test]
fn signal_scope_blocks_cross_domain_signal() {
    if !arapuca::landlock::signal_scope_supported() {
        eprintln!("skipping: Landlock ABI < 6 (no Scope::Signal)");
        return;
    }
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    let script = r#"
import os, sys
target = int(sys.argv[1])
try:
    os.kill(target, 0)
    print("KILL_OK")
except PermissionError:
    print("KILL_EPERM")
"#;
    // The test process is outside the sandbox's Landlock domain.
    let scoped = run_target(&[], script, std::process::id());
    let stdout = String::from_utf8_lossy(&scoped.stdout);
    assert!(
        scoped.status.success() && stdout.contains("KILL_EPERM"),
        "scoped run must deny the cross-domain signal: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&scoped.stderr)
    );

    let unscoped = run_target(&["--seccomp", "baseline"], script, std::process::id());
    let stdout = String::from_utf8_lossy(&unscoped.stdout);
    assert!(
        unscoped.status.success() && stdout.contains("KILL_OK"),
        "baseline control must allow the signal: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&unscoped.stderr)
    );
}
