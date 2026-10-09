//! macOS integration coverage for the opt-in TCP listener capability.
#![cfg(target_os = "macos")]

use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;

fn arapuca_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // test binary
    path.pop(); // deps
    path.push("arapuca");
    path
}

#[test]
fn macos_listener_permission_is_opt_in_and_external_egress_stays_denied() {
    let test_binary = std::env::current_exe().unwrap();
    let test_binary_dir = test_binary.parent().unwrap();
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--allow-network-listeners",
            "-v",
            &format!("{}:ro", test_binary_dir.display()),
            "--env",
            "ARKAI_ARAPUCA_LISTENER_HELPER=1",
            "--",
        ])
        .arg(&test_binary)
        .args(["--exact", "macos_listener_capability_helper", "--nocapture"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "listener helper failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn macos_listener_permission_is_denied_by_default() {
    let test_binary = std::env::current_exe().unwrap();
    let test_binary_dir = test_binary.parent().unwrap();
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "-v",
            &format!("{}:ro", test_binary_dir.display()),
            "--env",
            "ARKAI_ARAPUCA_LISTENER_HELPER=1",
            "--env",
            "ARKAI_ARAPUCA_LISTENER_DENIAL=1",
            "--",
        ])
        .arg(&test_binary)
        .args(["--exact", "macos_listener_capability_helper", "--nocapture"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "default-deny helper failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn macos_listener_capability_helper() {
    if std::env::var_os("ARKAI_ARAPUCA_LISTENER_HELPER").is_none() {
        return;
    }

    if std::env::var_os("ARKAI_ARAPUCA_LISTENER_DENIAL").is_some() {
        assert!(
            TcpListener::bind(("127.0.0.1", 0)).is_err(),
            "loopback bind must remain denied unless explicitly enabled"
        );
        return;
    }

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback bind should be allowed");
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).expect("loopback connect should be allowed");
    let (accepted, _) = listener
        .accept()
        .expect("loopback accept should be allowed");
    drop((client, accepted));

    // Seatbelt does not provide a reliable loopback-only bind/inbound filter.
    // Pin the current limitation so callers do not mistake this capability
    // for a loopback-only security boundary.
    let wildcard = TcpListener::bind(("0.0.0.0", 0))
        .expect("macOS Seatbelt's listener permission also permits wildcard bind");
    drop(wildcard);

    let external = TcpStream::connect_timeout(
        &"203.0.113.1:443".parse().unwrap(),
        Duration::from_millis(250),
    );
    assert!(
        external.is_err(),
        "listener permission must not allow external egress"
    );
}
