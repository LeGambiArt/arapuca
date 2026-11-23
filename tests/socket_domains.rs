//! Integration tests for the socket-domain allowlist
//! (`restrict_socket_domains`): exotic families (AF_VSOCK above all,
//! which bypasses network namespaces) EPERM under Strict, while
//! AF_NETLINK and the Baseline-permitted families keep working.

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

fn run(args: &[&str], script: &str) -> std::process::Output {
    let mut cmd = Command::new(arapuca_bin());
    cmd.args(["run"])
        .args(args)
        .arg("--")
        .args(["/usr/bin/python3", "-c", script]);
    cmd.output().unwrap()
}

/// The socket-domain probe reports one line per family tried.
const PROBE: &str = r#"
import socket, errno
def probe(name, fn):
    try:
        fn()
        print(name, "OK")
    except PermissionError:
        print(name, "EPERM")
    except OSError as e:
        print(name, "ERR", errno.errorcode.get(e.errno, e.errno))
probe("VSOCK", lambda: socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM))
probe("NETLINK", lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16))
probe("PACKET", lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW))
probe("INET", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM))
"#;

#[test]
fn socket_domains_restricted_in_strict() {
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    let out = run(&[], PROBE);
    assert!(
        out.status.success(),
        "strict run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The gap being closed: AF_VSOCK reaches past the network
    // namespace; AF_PACKET sniffs. Both must EPERM now.
    assert!(
        stdout.contains("VSOCK EPERM"),
        "AF_VSOCK must EPERM under Strict: {stdout}"
    );
    assert!(
        stdout.contains("PACKET EPERM"),
        "AF_PACKET must EPERM under Strict: {stdout}"
    );
    // Kept on purpose: interface enumeration in common libraries.
    assert!(
        stdout.contains("NETLINK OK"),
        "AF_NETLINK must stay allowed: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Strict denies inet by its own (pre-existing) rule; the
    // allowlist must not have relaxed it.
    assert!(
        stdout.contains("INET EPERM"),
        "AF_INET must stay denied in Strict: {stdout}"
    );
}

/// Baseline keeps AF_INET (loopback listeners), and the allowlist is
/// off by default there — so every probe succeeds except the exotic
/// families when explicitly enabled. The default-off control proves
/// the Strict denials come from this tier, not from the kernel.
#[test]
fn socket_domains_baseline_control() {
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    let out = run(&["--seccomp", "baseline"], PROBE);
    assert!(
        out.status.success(),
        "baseline run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("INET OK"),
        "baseline must keep AF_INET: {stdout}"
    );
    assert!(
        stdout.contains("NETLINK OK"),
        "baseline must keep AF_NETLINK: {stdout}"
    );
    // Baseline restricts the exotic families only when explicitly
    // asked; there is no CLI flag for it yet, so the default run
    // shows them still open — the discriminating control for the
    // Strict-tier assertions above. (socket() succeeds without a
    // vsock device: creation is the capability being gated.)
    assert!(
        stdout.contains("VSOCK OK"),
        "baseline default must not restrict AF_VSOCK (no explicit opt-in): {stdout}"
    );
}
