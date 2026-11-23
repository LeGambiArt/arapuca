//! Integration tests for SysV IPC isolation (`use_ipcns`): without
//! an IPC namespace, a sandboxed process can `shmat` by ID onto any
//! segment owned by the same uid — X11 MIT-SHM buffers included.

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

fn netns_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--net", "--map-root-user", "--", "/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The probe: shmat onto a host-created segment by ID. Inside a new
/// IPC namespace the ID does not resolve, so the attach fails.
const PROBE: &str = r#"
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
libc.shmat.restype = ctypes.c_void_p
shmid = int(sys.argv[1])
ctypes.set_errno(0)
addr = libc.shmat(shmid, None, 0)
if addr == ctypes.c_void_p(-1).value:
    print("SHMAT_FAIL", ctypes.get_errno())
else:
    print("SHMAT_OK")
"#;

fn run(args: &[&str], shmid: i32) -> std::process::Output {
    let mut cmd = Command::new(arapuca_bin());
    cmd.args(["run"])
        .args(args)
        .arg("--")
        .args(["/usr/bin/python3", "-c", PROBE])
        .arg(shmid.to_string());
    cmd.output().unwrap()
}

#[test]
fn sysv_shm_isolated_in_namespace_launch() {
    if !python3_available() || !netns_available() {
        eprintln!("skipping: requires python3 and user/net namespaces");
        return;
    }

    // Host segment created by the test process (same uid as the
    // sandbox target — exactly the scenario being closed).
    let shmid = unsafe { libc::shmget(libc::IPC_PRIVATE, 4096, libc::IPC_CREAT | 0o600) };
    assert!(shmid >= 0, "shmget in the test process failed");

    let out = run(&["--deny-network", "--seccomp", "baseline"], shmid);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("SHMAT_FAIL"),
        "shmat onto a host segment must fail inside the IPC namespace: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Control: a plain launch (no namespace machinery active) keeps
    // host SysV IPC, proving the failure is the namespace and not
    // the probe.
    let out = run(&["--seccomp", "baseline"], shmid);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("SHMAT_OK"),
        "plain-launch control must reach the host segment: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    unsafe { libc::shmctl(shmid, libc::IPC_RMID, std::ptr::null_mut()) };
}
