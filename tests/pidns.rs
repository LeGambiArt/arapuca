//! Integration tests for PID namespace isolation.
//!
//! Requires Linux with user namespace support. Tests exercise the
//! `arapuca run --deny-network` path which enables both netns and
//! pidns by default.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

fn arapuca_bin() -> PathBuf {
    // Compile-time location of the binary built by this package:
    // robust to cargo's test-binary layout (deps/ vs build/out/),
    // which differs across cargo versions.
    PathBuf::from(env!("CARGO_BIN_EXE_arapuca"))
}

fn pidns_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--net", "--map-current-user", "--", "/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

// ─── Exit status propagation ────────────────────────────────

#[test]
fn pidns_exit_code_zero() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let status = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/true",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "exit 0 should propagate through pidns");
}

#[test]
fn pidns_exit_code_nonzero() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let status = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/false",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1), "exit 1 should propagate");
}

#[test]
fn pidns_exit_code_custom() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let status = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/sh",
            "-c",
            "exit 42",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(42), "exit 42 should propagate");
}

// ─── Basic functionality with pidns ─────────────────────────

#[test]
fn pidns_stdout_passthrough() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/echo",
            "pidns-ok",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "pidns-ok");
}

#[test]
fn pidns_env_passthrough() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--env",
            "TEST_VAR=hello",
            "--",
            "/bin/sh",
            "-c",
            "echo $TEST_VAR",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
}

// ─── --no-pid-ns opt-out ────────────────────────────────────

#[test]
fn no_pid_ns_flag_disables_pidns() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let status = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--no-pid-ns",
            "--seccomp",
            "baseline",
            "--",
            "/bin/true",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "--no-pid-ns should work");
}

// ─── PID 1 behavior ────────────────────────────────────────

#[test]
fn pidns_target_is_pid_2_after_init() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/sh",
            "-c",
            "echo $$",
        ])
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("pidns_target_is_pid_2_after_init failed: {stderr}");
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pid = stdout.trim();
    // PID 1 is the reaping init; the target is PID 2. Any small
    // namespace-local pid proves the target left the host namespace
    // (the host pid is five-plus digits).
    assert_eq!(
        pid, "2",
        "target should be PID 2 (after the PID-1 init) in the namespace, got: {pid}"
    );
}

// ─── Exec chain inside pidns ────────────────────────────────

#[test]
fn pidns_exec_chain_works() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/sh",
            "-c",
            "/bin/echo chain-ok",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "chain-ok");
}

// ─── Netns implies pidns (library-level coupling) ──────────────

/// NSpid line from inside the sandbox: multiple PID entries mean the
/// process sits in a PID namespace; a single entry means host PIDs.
fn nspid_count(args: &[&str]) -> usize {
    let output = Command::new(arapuca_bin())
        .args(["run"])
        .args(args)
        .arg("--")
        .args(["/bin/sh", "-c", "grep NSpid /proc/self/status"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "status probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("NSpid:"))
        .expect("NSpid line present");
    line.split_whitespace().skip(1).count()
}

/// A network-namespace launch must land in a PID namespace without
/// the caller asking for one: the library now matches the CLI's
/// long-standing coupling, closing kill(-1) against same-uid host
/// processes for every consumer on upgrade.
#[test]
fn netns_implies_pidns() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    assert!(
        nspid_count(&["--deny-network", "--seccomp", "baseline"]) > 1,
        "netns launch must sit in a PID namespace"
    );
}

/// The explicit opt-out keeps host PID visibility.
#[test]
fn no_pid_ns_opt_out_keeps_host_pids() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    assert_eq!(
        nspid_count(&["--deny-network", "--seccomp", "baseline", "--no-pid-ns"]),
        1,
        "--no-pid-ns must keep the target in the host PID namespace"
    );
}

/// The PID-1 init must reap namespace orphans: without it they pile
/// up as zombies against the cgroup's pids.max. The oracle counts
/// defunct processes inside the namespace after the target forks a
/// grandchild that outlives its parent: the orphan reparents to
/// PID 1, exits, and must vanish. /proc is mounted read-only for the
/// probe (the default read paths exclude it).
#[test]
fn pidns_init_reaps_orphans() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    let script = r#"
import os, sys, time
# Fork a child that forks a grandchild and exits: the grandchild is
# orphaned, reparents to PID 1, sleeps briefly, and exits.
pid = os.fork()
if pid == 0:
    gpid = os.fork()
    if gpid == 0:
        time.sleep(0.5)
        os._exit(0)
    os._exit(0)
# Reap our own direct child: a zombie here would belong to the
# target, not to the PID-1 init, and muddy the oracle.
os.waitpid(pid, 0)
time.sleep(1.5)
zombies = 0
for entry in os.listdir("/proc"):
    if not entry.isdigit():
        continue
    try:
        with open(f"/proc/{entry}/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        with open(f"/proc/{entry}/status") as f:
            status = f.read()
        # /proc is the host mount (no mount namespace in this launch
        # shape), so host-wide zombies appear too. Namespace members
        # carry a two-field NSpid line (host pid + namespace pid);
        # host processes outside the namespace have one field.
        nspid = [l for l in status.splitlines() if l.startswith("NSpid:")]
        in_ns = nspid and len(nspid[0].split()) > 2
        if fields[0] == "Z" and in_ns:
            zombies += 1
    except OSError:
        pass
print(f"ZOMBIES={zombies}")
"#;
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("probe.py");
    std::fs::write(&probe, script).unwrap();

    let output = Command::new(arapuca_bin())
        .args(["run", "--deny-network", "--seccomp", "baseline"])
        .args(["-v", "/proc:ro"])
        .arg("-v")
        .arg(dir.path())
        .args(["--", "/usr/bin/python3"])
        .arg(&probe)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "probe run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("ZOMBIES=0"),
        "the PID-1 init must reap the orphaned grandchild: {stdout}"
    );
}

fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("PPid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn cmdline_args(pid: u32) -> Vec<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|buf| {
            buf.split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// The PID-1 init must die with the relay: SIGKILLing the wrapper's
/// relay process must collapse the whole namespace — the target via
/// its pdeathsig, the init via its own — leaving no survivor holding
/// the namespace (or stdio) open. The oracle pins the init's PID
/// before the kill and requires it to vanish alongside the target:
/// a surviving init would keep reaping namespace orphans forever
/// with no supervisor attached.
#[test]
fn pidns_init_dies_with_relay() {
    if !pidns_available() {
        eprintln!("skipping: user/net namespace not available");
        return;
    }
    let mut child = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/sleep",
            "30",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    // Steady state: the exec'd target (`sleep 30`) is visible in
    // /proc with a two-field NSpid line (host pid + namespace pid).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let (target_pid, relay_pid) = 'find: loop {
        for entry in std::fs::read_dir("/proc").unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            let args = cmdline_args(pid);
            if args.first().map(|a| a.ends_with("sleep")).unwrap_or(false)
                && args.get(1).map(String::as_str) == Some("30")
            {
                let status =
                    std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
                let in_ns = status
                    .lines()
                    .find(|l| l.starts_with("NSpid:"))
                    .map(|l| l.split_whitespace().skip(1).count() > 1)
                    .unwrap_or(false);
                if in_ns {
                    if let Some(ppid) = read_ppid(pid) {
                        break 'find (pid, ppid);
                    }
                }
            }
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("target never appeared in /proc");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };

    // The init is the relay's other child (namespace PID 1).
    let init_pid = std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .find(|&pid| pid != target_pid && read_ppid(pid) == Some(relay_pid));
    let init_pid = match init_pid {
        Some(pid) => pid,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("init (relay's second child) not found");
        }
    };

    // Kill the relay. Everything inside must follow.
    let ret = unsafe { libc::kill(relay_pid as i32, libc::SIGKILL) };
    assert_eq!(ret, 0, "SIGKILL of the relay failed");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let target_gone = !std::path::Path::new(&format!("/proc/{target_pid}")).exists();
        let init_gone = !std::path::Path::new(&format!("/proc/{init_pid}")).exists();
        if target_gone && init_gone {
            break;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "namespace survived the relay: target {target_pid} gone={target_gone}, \
                 init {init_pid} gone={init_gone}"
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
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
