//! Integration tests for the filesystem-metadata denial tier
//! (`deny_fs_metadata`): chmod/chown/xattr/utime/truncate-class
//! syscalls EPERM in Strict, with `ftruncate` kept as the documented
//! carve-out for in-place content mutation.

#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
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

/// chmod on a granted write path EPERMs under Strict (the default)
/// and works under Baseline — the control that proves the tier, not
/// Landlock, is what denies it. The file mode must not change in the
/// Strict run.
#[test]
fn fs_metadata_chmod_denied_in_strict() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("f");
    std::fs::write(&f, "x").unwrap();
    let script = format!("chmod 600 {}; echo rc=$?", f.display());

    let out = {
        let mut cmd = Command::new(arapuca_bin());
        cmd.args(["run", "-v"])
            .arg(dir.path())
            .args(["--", "/bin/sh", "-c", &script]);
        cmd.output().unwrap()
    };
    assert!(
        out.status.success(),
        "strict run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("rc=1"),
        "chmod must EPERM under Strict: {stdout}"
    );
    let mode = std::fs::metadata(&f).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o644, "mode must be unchanged under Strict");

    let out = {
        let mut cmd = Command::new(arapuca_bin());
        cmd.args(["run", "-v"])
            .arg(dir.path().to_str().unwrap())
            .args(["--seccomp", "baseline"])
            .args(["--", "/bin/sh", "-c", &script]);
        cmd.output().unwrap()
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("rc=0"),
        "baseline control must allow chmod: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The carve-out: ftruncate through a write-open fd keeps working in
/// Strict, so in-place content mutation inside granted write paths
/// is intact. Path-based truncate is denied.
#[test]
fn ftruncate_carve_out_still_works() {
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("f");
    std::fs::write(&f, "hello").unwrap();

    let script = format!(
        "import os\nfd = os.open({p:?}, os.O_WRONLY)\nos.ftruncate(fd, 1)\nos.close(fd)\nprint('FT_OK')\nfd2 = os.open({p:?}, os.O_RDONLY)\ntry:\n    os.fchmod(fd2, 0o600)\n    print('FCHMOD_OK')\nexcept PermissionError:\n    print('FCHMOD_EPERM')\n",
        p = f.display().to_string()
    );
    let out = {
        let mut cmd = Command::new(arapuca_bin());
        cmd.args(["run", "-v"])
            .arg(dir.path())
            .args(["--", "/usr/bin/python3", "-c", &script]);
        cmd.output().unwrap()
    };
    assert!(
        out.status.success(),
        "strict run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("FT_OK"),
        "ftruncate must keep working: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The security review's headline: fchmod works on O_RDONLY
    // descriptors, so the fd variants must be denied too.
    assert!(
        stdout.contains("FCHMOD_EPERM"),
        "fchmod on an O_RDONLY fd must EPERM: {stdout}"
    );
    let content = std::fs::read_to_string(&f).unwrap();
    assert_eq!(content, "h", "ftruncate must have shrunk the file");
}
