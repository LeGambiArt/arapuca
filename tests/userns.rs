//! Integration tests for `--userns`: the standalone user-namespace
//! isolation layer (current uid/gid mapped 1:1, capless target, host
//! network shared).
//!
//! This layer is isolation-hardening only — it is not a Yama
//! mechanism and carries no policy. The tests pin its observable
//! contract: the identity mapping, the cleared capabilities, the
//! shared host network, unchanged Landlock enforcement, the
//! combination-rule rejections, and the honest supplementary-group
//! behavior (groups are retained at the kernel level and appear as
//! the overflow gid in userspace — group-gated DAC access still
//! works inside the namespace).

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn arapuca_bin() -> PathBuf {
    // Compile-time location of the binary built by this package:
    // robust to cargo's test-binary layout (deps/ vs build/out/),
    // which differs across cargo versions.
    PathBuf::from(env!("CARGO_BIN_EXE_arapuca"))
}

fn userns_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--map-current-user", "--", "/bin/true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn python3_available() -> bool {
    Command::new("python3")
        .arg("-c")
        .arg("pass")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn yama_scope() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn run_userns(args: &[&str], script: &str) -> std::process::Output {
    let mut cmd = Command::new(arapuca_bin());
    cmd.args(["run", "--userns", "--seccomp", "baseline"])
        .args(args)
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(script);
    cmd.output().unwrap()
}

#[test]
fn userns_maps_identity_and_clears_capabilities() {
    // The safe state: uid/gid mapped 1:1 (a real uid_map exists),
    // and the mapping of a non-root uid clears the user-namespace
    // capabilities across the exec — the target is capless. Root's
    // unmapped files appear owned by the overflow uid.
    if !userns_available() || !python3_available() {
        eprintln!("skipping: requires userns and python3");
        return;
    }
    let script = r#"
import os
uid = os.getuid()
gid = os.getgid()
uid_map = open("/proc/self/uid_map").read()
gid_map = open("/proc/self/gid_map").read()
cap_eff = [l for l in open("/proc/self/status") if l.startswith("CapEff")][0].split()[1]
shadow_uid = os.stat("/etc/shadow").st_uid
outside_uid = int(os.environ["USERNS_TEST_OUTSIDE_UID"])
outside_gid = int(os.environ["USERNS_TEST_OUTSIDE_GID"])
assert uid == outside_uid, (uid, outside_uid)
assert gid == outside_gid, (gid, outside_gid)
uid_fields = uid_map.split()
assert uid_fields == [str(outside_uid), str(outside_uid), "1"], uid_map
gid_fields = gid_map.split()
assert gid_fields == [str(outside_gid), str(outside_gid), "1"], gid_map
assert int(cap_eff, 16) == 0, cap_eff
assert shadow_uid == 65534, shadow_uid
print("IDENTITY_OK")
"#;
    // The outside identity travels via the target environment (--env
    // values are visible to the target).
    let out = {
        let mut cmd = Command::new(arapuca_bin());
        cmd.args(["run", "--userns", "--seccomp", "baseline"])
            .arg("--env")
            .arg(format!("USERNS_TEST_OUTSIDE_UID={}", users_id("uid")))
            .arg("--env")
            .arg(format!("USERNS_TEST_OUTSIDE_GID={}", users_id("gid")))
            .arg("--")
            .arg("python3")
            .arg("-c")
            .arg(script);
        cmd.output().unwrap()
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("IDENTITY_OK"),
        "identity/capability contract must hold: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The test process's own uid/gid via the id(1) utility.
fn users_id(kind: &str) -> String {
    let flag = match kind {
        "uid" => "-u",
        "gid" => "-g",
        _ => unreachable!(),
    };
    let out = Command::new("id").arg(flag).output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn userns_shares_host_network() {
    // No network namespace: the target must reach a listener the
    // test process holds on loopback (netns modes cannot).
    if !userns_available() || !python3_available() {
        eprintln!("skipping: requires userns and python3");
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let serve = std::thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            let _ = conn.write_all(b"host-net");
            let mut buf = [0u8; 16];
            let _ = conn.read(&mut buf);
        }
    });
    let script = format!(
        r#"
import socket
c = socket.create_connection(("127.0.0.1", {port}), timeout=10)
data = c.recv(16)
assert data == b"host-net", data
print("HOST_NET_OK")
"#,
        port = port
    );
    let out = run_userns(&[], &script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("HOST_NET_OK"),
        "target must share the host network: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = serve.join();
}

#[test]
fn userns_keeps_landlock_enforcement() {
    // The user namespace must not loosen the filesystem sandbox:
    // a world-readable file outside the granted paths stays denied
    // (strict profile — /proc and friends are not granted).
    if !userns_available() || !python3_available() {
        eprintln!("skipping: requires userns and python3");
        return;
    }
    let out = Command::new(arapuca_bin())
        .args(["run", "--userns", "--"])
        .arg("python3")
        .arg("-c")
        .arg(
            r#"
try:
    open("/etc/hostname", "rb").read(8)
    print("UNEXPECTED_READ")
except OSError as e:
    assert e.errno == 13, e.errno
    print("LANDLOCK_OK")
"#,
        )
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("LANDLOCK_OK"),
        "Landlock must stay enforced under --userns: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn userns_groups_retained_as_overflow() {
    // Honest contract, deliberately pinned: supplementary groups are
    // NOT dropped by `unshare --user --map-current-user`. The kernel
    // keeps the real gids (group-gated DAC access still works — see
    // userns_group_gated_access_still_works), and userspace shows
    // every unmapped gid as the overflow gid 65534.
    if !userns_available() || !python3_available() {
        eprintln!("skipping: requires userns and python3");
        return;
    }
    let script = r#"
import os
outside = sorted(int(g) for g in os.environ["USERNS_TEST_GROUPS"].split())
inside = sorted(os.getgroups())
expected = sorted(65534 if g != os.getgid() else g for g in outside)
# The primary gid may or may not appear in the supplementary list
# depending on the host user; every entry must match the transform.
assert inside == expected or inside == sorted(set(expected)), (inside, expected)
mapped = [g for g in inside if g != 65534]
assert all(g == os.getgid() for g in mapped), (mapped, os.getgid())
print("GROUPS_OK", inside)
"#;
    let groups = {
        let out = Command::new("id").arg("-G").output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let out = Command::new(arapuca_bin())
        .args([
            "run",
            "--userns",
            "--seccomp",
            "baseline",
            "--env",
            &format!("USERNS_TEST_GROUPS={groups}"),
            "--",
        ])
        .arg("python3")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("GROUPS_OK"),
        "group transform contract must hold: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn userns_group_gated_access_still_works() {
    // The companion to the pinned group contract: a file gated to
    // one of the user's supplementary groups (mode 0640, group not
    // the primary) remains readable inside the namespace — the
    // kernel group list survives the 1:1 mapping. If group
    // isolation is ever needed, the unix socket connect policy is
    // the enforcement point, not --userns.
    if !userns_available() || !python3_available() {
        eprintln!("skipping: requires userns and python3");
        return;
    }
    // Pick a supplementary group other than the primary gid.
    let (primary, supplementary) = {
        let gid = users_id("gid");
        let out = Command::new("id").arg("-G").output().unwrap();
        let groups: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        match groups.iter().find(|g| **g != gid) {
            Some(g) => (gid, g.clone()),
            None => {
                eprintln!("skipping: test user has no supplementary groups");
                return;
            }
        }
    };
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("grouped.txt");
    std::fs::write(&file, "group-gated\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(&file).unwrap().permissions();
    perms.set_mode(0o640);
    std::fs::set_permissions(&file, perms).unwrap();
    let group_cmd = Command::new("chgrp")
        .arg(&supplementary)
        .arg(&file)
        .status();
    if group_cmd.is_err() || !group_cmd.unwrap().success() {
        eprintln!("skipping: cannot chgrp test file");
        return;
    }
    let out = Command::new(arapuca_bin())
        .args([
            "run",
            "--userns",
            "--seccomp",
            "baseline",
            "-v",
            &format!("{}:ro", dir.path().display()),
            "--",
        ])
        .arg("python3")
        .arg("-c")
        .arg(format!(
            r#"
data = open({file:?}).read()
assert data == "group-gated\n", data
print("GROUP_DAC_OK")
"#,
            file = file.display().to_string()
        ))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("GROUP_DAC_OK"),
        "group-gated DAC must still apply inside --userns: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = primary;
}

#[test]
fn userns_combination_flags_rejected() {
    // The netns-implying modes already create a user namespace with
    // a root mapping; combining them with --userns is ambiguous and
    // rejected rather than resolved.
    if !userns_available() {
        eprintln!("skipping: requires userns");
        return;
    }
    let combinations: &[&[&str]] = &[
        &["--deny-network"],
        &["--allow-network-listeners"],
        &["--allow-host", "example.com:443"],
        &["--proxy-socket", "/run/does-not-exist.sock"],
    ];
    for combo in combinations {
        let mut cmd = Command::new(arapuca_bin());
        cmd.args(["run", "--userns"])
            .args(combo.iter().copied())
            .arg("--")
            .arg("/bin/true");
        let out = cmd.output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(125),
            "--userns + {combo:?} must be rejected"
        );
        assert!(
            stderr.contains("--userns is exclusive"),
            "rejection must name the conflict: {stderr}"
        );
    }
}

#[test]
fn userns_unix_socket_policy_enforces() {
    // The policy works under --userns at Yama scopes 0/1: the
    // capless supervisor inspects its child without a namespace.
    // Denied-root connects get EACCES; ordinary ones keep working.
    if !userns_available() || !python3_available() {
        eprintln!("skipping: requires userns and python3");
        return;
    }
    if yama_scope() > 1 {
        eprintln!(
            "skipping: yama ptrace_scope={} denies the capless supervisor (need <= 1)",
            yama_scope()
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let deny_root = dir.path().join("denyroot");
    std::fs::create_dir(&deny_root).unwrap();
    let denied_path = deny_root.join("denied.sock");
    let benign_path = dir.path().join("benign.sock");
    let denied_listener = std::os::unix::net::UnixListener::bind(&denied_path).unwrap();
    // No accept loop for the denied listener: a correct broker never
    // dials it. A regression that does lets the connect succeed,
    // which the target's assertion catches.
    let benign_listener = std::os::unix::net::UnixListener::bind(&benign_path).unwrap();
    let serve_benign = std::thread::spawn(move || {
        if let Ok((mut conn, _)) = benign_listener.accept() {
            let _ = conn.write_all(b"ack");
        }
    });
    let script = format!(
        r#"
import socket
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect({denied:?})
    print("DENIED_UNEXPECTEDLY")
except OSError as e:
    assert e.errno == 13, e.errno
    print("DENIED_OK")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect({benign:?})
assert s.recv(16) == b"ack"
print("BENIGN_OK")
"#,
        denied = denied_path.display().to_string(),
        benign = benign_path.display().to_string()
    );
    let out = Command::new(arapuca_bin())
        .args([
            "run",
            "--userns",
            "--seccomp",
            "baseline",
            "--deny-privileged-unix-sockets",
            "--unix-socket-deny-root",
            &deny_root.display().to_string(),
            "--",
        ])
        .arg("python3")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("DENIED_OK") && stdout.contains("BENIGN_OK"),
        "policy must enforce under --userns: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The benign thread ends with the connection; the denied listener
    // must never have seen one (the broker denies before dialing).
    drop(denied_listener);
    let _ = serve_benign.join();
    drop(dir);
}

#[test]
fn userns_exit_codes_propagate() {
    if !userns_available() {
        eprintln!("skipping: requires userns");
        return;
    }
    let out = Command::new(arapuca_bin())
        .args(["run", "--userns", "--"])
        .arg("/bin/sh")
        .arg("-c")
        .arg("echo stdout-ok; exit 7")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(7));
    assert!(stdout.contains("stdout-ok"), "{stdout}");
}

// ─── Audit events (library API) ───────────────────────────────

#[test]
fn userns_reports_layer_and_never_netns() {
    // The audit trail must report the user namespace as its own
    // layer and must NOT report network-namespace isolation: --userns
    // never leaks into netns eligibility.
    if !userns_available() {
        eprintln!("skipping: requires userns");
        return;
    }
    struct VecSink(std::sync::Mutex<Vec<arapuca::audit::AuditEvent>>);
    impl arapuca::audit::AuditSink for VecSink {
        fn emit(&self, event: arapuca::audit::AuditEvent) {
            self.0.lock().unwrap().push(event);
        }
    }
    let sink = std::sync::Arc::new(VecSink(std::sync::Mutex::new(Vec::new())));

    let cfg = arapuca::Config {
        profile: arapuca::Profile {
            use_userns: true,
            seccomp_profile: arapuca::SeccompProfile::Baseline,
            ..Default::default()
        },
        socket_dir: PathBuf::new(),
        task_id: "userns-audit".into(),
        phase: "test".into(),
        work_dir: None,
        stdin: None,
        stdout: None,
        stderr: None,
        extra_fds: Vec::new(),
        tty: false,
        network_proxy_socket: None,
        allowed_hosts: Vec::new(),
        env: Vec::new(),
        audit_sink: Some(sink.clone()),
        audit_verbosity: arapuca::audit::AuditVerbosity::Standard,
        audit_principal: None,
        audit_correlation_id: None,
    };
    use arapuca::platform::Sandbox;
    let sandbox = arapuca::platform::new().unwrap();
    let mut proc = sandbox
        .launch(&cfg, "/bin/true", &[])
        .expect("userns launch");
    let _ = proc.wait();

    use arapuca::audit::{AuditEvent, SandboxLayer};
    let events = sink.0.lock().unwrap();
    let applied = events.iter().any(|e| {
        matches!(
            e,
            AuditEvent::LayerApplied {
                layer: SandboxLayer::UserNamespace,
                ..
            }
        )
    });
    let netns_applied = events.iter().any(|e| {
        matches!(
            e,
            AuditEvent::LayerApplied {
                layer: SandboxLayer::NetworkNamespace,
                ..
            }
        )
    });
    assert!(applied, "UserNamespace layer must be reported as applied");
    assert!(
        !netns_applied,
        "--userns must not report network namespace isolation"
    );
}
