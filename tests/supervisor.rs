//! Integration tests for the supervisor-as-parent topology.
//!
//! The unotify supervisor is spawned by the launcher as the target's
//! parent (instead of the legacy child topology). These tests cover
//! the topology's acceptance criteria: terminal signal routing, the
//! supervisor death chain (PDEATHSIG), the setsid semantics of the
//! group-leader design, the pidns handover, signaling through the
//! pid-report, fd hygiene, executable pinning across both execs, and
//! the cgroup sync byte consumed by the supervisor before its fork.
//!
//! Tests that need the supervisor force it with
//! `--deny-privileged-unix-sockets`: the policy fails closed without
//! one, so a successful run proves the supervisor was present. This
//! is independent of the optional serde feature, which gates only
//! the audit-driven spawn path.
//!
//! The supervisor needs Yama ptrace: plain runs at scope 0/1, netns
//! runs at scopes 0-2. Scope 3 denies everything unconditionally —
//! those tests skip until the host reboots (Yama's sysctl latches
//! one-way upward).

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn arapuca_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.push("arapuca");
    path
}

fn yama_scope() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// The plain-run supervisor inspects its child, which Yama permits at
/// scopes 0/1. At scope 2 the capless prober is denied; at 3 so is
/// everything else.
fn plain_supervisor_available() -> bool {
    yama_scope() <= 1
}

fn netns_root_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--net", "--map-root-user", "--", "/bin/true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Inside a user namespace the supervisor holds capabilities, so it
/// can inspect its child at Yama scopes 0-2. Only scope 3 denies.
fn netns_supervisor_available() -> bool {
    netns_root_available() && yama_scope() < 3
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

fn cgroup_available() -> bool {
    Command::new(arapuca_bin())
        .args(["run", "--memory", "256", "--", "/bin/true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A launched run whose stdout and stderr are captured by reader
/// threads, so the test can react to markers while it runs.
struct SpawnedRun {
    child: std::process::Child,
    output: Arc<Mutex<String>>,
}

impl SpawnedRun {
    fn spawn(mut cmd: Command) -> Self {
        cmd.stdin(Stdio::null());
        let mut child = loop {
            match cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
                Ok(c) => break c,
                // ETXTBSY: the binary-swap race replaced the binary
                // under this exec — same class as the decoy "run"
                // log-line case, retry instead of panicking.
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("spawn arapuca: {e}"),
            }
        };
        let output = Arc::new(Mutex::new(String::new()));
        let mut streams: Vec<Box<dyn Read + Send>> = Vec::new();
        if let Some(s) = child.stdout.take() {
            streams.push(Box::new(s));
        }
        if let Some(s) = child.stderr.take() {
            streams.push(Box::new(s));
        }
        for mut stream in streams {
            let output = Arc::clone(&output);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => output
                            .lock()
                            .unwrap()
                            .push_str(&String::from_utf8_lossy(&buf[..n])),
                    }
                }
            });
        }
        Self { child, output }
    }

    /// Wait until the combined output contains `marker`.
    fn wait_for(&mut self, marker: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.output.lock().unwrap().contains(marker) {
                return true;
            }
            if let Ok(Some(_)) = self.child.try_wait() {
                return self.output.lock().unwrap().contains(marker);
            }
            if Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Wait for exit with a deadline: a regression that hangs must
    /// fail the test, not block the suite.
    fn wait(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status);
            }
            if Instant::now() > deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn output(&self) -> String {
        self.output.lock().unwrap().clone()
    }
}

/// PIDs whose parent is `pid`, by scanning /proc (the optional
/// /proc/<pid>/task/*/children file is not universal).
fn children_of(pid: u32) -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(format!("/proc/{name}/status")) else {
            continue;
        };
        let in_cgroup = status.lines().any(|l| {
            l.strip_prefix("PPid:")
                .and_then(|v| v.trim().parse::<u32>().ok())
                .is_some_and(|ppid| ppid == pid)
        });
        if in_cgroup {
            if let Ok(n) = name.parse::<i32>() {
                out.push(n);
            }
        }
    }
    out
}

fn pid_alive(pid: i32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

fn open_ptty() -> (std::fs::File, std::fs::File) {
    let mut master: i32 = 0;
    let mut slave: i32 = 0;
    // SAFETY: openpty with valid out-pointers; null name/termios.
    let ret = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(ret, 0, "openpty");
    // SAFETY: on success both descriptors are valid and owned.
    unsafe {
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
        )
    }
}

// ─── Terminal signals (tty Ctrl-C) ────────────────────────────

/// Read the master side into `output` until EOF, and return a writer
/// handle to it.
fn spawn_master_reader(master: std::fs::File) -> (std::fs::File, Arc<Mutex<String>>) {
    let writer = master.try_clone().expect("clone pty master");
    let output = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&output);
    std::thread::spawn(move || {
        let mut master = master;
        let mut buf = [0u8; 4096];
        loop {
            match master.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => sink
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n])),
            }
        }
    });
    (writer, output)
}

fn run_tty_target(script: &str) -> (std::process::Child, Arc<Mutex<String>>, std::fs::File) {
    let (master, slave) = open_ptty();
    let mut cmd = Command::new(arapuca_bin());
    cmd.args([
        "run",
        "-t",
        "--seccomp",
        "baseline",
        "--deny-privileged-unix-sockets",
        "--",
    ])
    .arg("/bin/sh")
    .arg("-c")
    .arg(script);
    cmd.stdin(Stdio::from(slave.try_clone().expect("clone slave")));
    cmd.stdout(Stdio::from(slave.try_clone().expect("clone slave")));
    cmd.stderr(Stdio::from(slave));
    let child = cmd.spawn().expect("spawn arapuca -t");
    let (writer, output) = spawn_master_reader(master);
    (child, output, writer)
}

#[test]
fn tty_ctrl_c_default_disposition_kills_target() {
    // The wrapper's process group is the terminal's foreground group:
    // Ctrl-C must kill a default-disposition target with SIGINT. The
    // supervisor sits outside that group — if the signal leaked to it,
    // the wrapper would die by PDEATHSIG (exit 137) instead.
    if !plain_supervisor_available() {
        eprintln!(
            "skipping: yama ptrace_scope={} denies the plain-run supervisor",
            yama_scope()
        );
        return;
    }
    let (mut child, output, mut writer) = run_tty_target("echo READY; sleep 30");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !output.lock().unwrap().contains("READY") && Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                panic!(
                    "target exited before Ctrl-C: {status}\n{}",
                    output.lock().unwrap()
                )
            }
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    assert!(
        output.lock().unwrap().contains("READY"),
        "target never became ready: {}",
        output.lock().unwrap()
    );

    writer.write_all(b"\x03").expect("send Ctrl-C");

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            _ => {
                assert!(
                    Instant::now() < deadline,
                    "target did not die on terminal SIGINT: {}",
                    output.lock().unwrap()
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    let code = status.code().unwrap_or(0);
    assert_eq!(
        code,
        130,
        "default-disposition target must die from SIGINT (130), got {code}\n{}",
        output.lock().unwrap()
    );
    let _ = child.wait();
}

#[test]
fn tty_ctrl_c_catching_target_supervisor_survives() {
    // A SIGINT-catching target handles the signal and exits with its
    // own code; the run must propagate that code. A supervisor hit by
    // the terminal signal would cascade a PDEATHSIG SIGKILL (137) and
    // swallow the target's exit path.
    if !plain_supervisor_available() {
        eprintln!(
            "skipping: yama ptrace_scope={} denies the plain-run supervisor",
            yama_scope()
        );
        return;
    }
    let (mut child, output, mut writer) =
        run_tty_target(r#"echo READY; trap 'echo HANDLED; exit 42' INT; sleep 30"#);

    let deadline = Instant::now() + Duration::from_secs(30);
    while !output.lock().unwrap().contains("READY") && Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                panic!(
                    "target exited before Ctrl-C: {status}\n{}",
                    output.lock().unwrap()
                )
            }
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    assert!(
        output.lock().unwrap().contains("READY"),
        "target never became ready: {}",
        output.lock().unwrap()
    );

    writer.write_all(b"\x03").expect("send Ctrl-C");

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            _ => {
                assert!(
                    Instant::now() < deadline,
                    "target did not handle terminal SIGINT: {}",
                    output.lock().unwrap()
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    let out = output.lock().unwrap().clone();
    let _ = child.wait();
    assert_eq!(
        status.code(),
        Some(42),
        "target exit code must propagate: {out}"
    );
    assert!(out.contains("HANDLED"), "trap must have run: {out}");
}

// ─── Supervisor death chain ────────────────────────────────────

#[test]
fn supervisor_death_sigkills_target() {
    // The wrapper re-arms PR_SET_PDEATHSIG(SIGKILL) against its
    // parent — the supervisor. Killing the supervisor must take the
    // wrapper/target down with SIGKILL, promptly, with the run
    // reporting the supervisor's death (137).
    if !plain_supervisor_available() || !python3_available() {
        eprintln!("skipping: requires plain-run supervisor and python3");
        return;
    }
    let script = r#"
import time
status = open("/proc/self/status").read()
ppid = int(status.split("PPid:")[1].split()[0])
import os
print("TGT", os.getpid(), flush=True)
print("SUP", ppid, flush=True)
time.sleep(120)
"#;
    let mut cmd = Command::new(arapuca_bin());
    cmd.args([
        "run",
        "--seccomp",
        "baseline",
        "--deny-privileged-unix-sockets",
        "--",
    ])
    .arg("python3")
    .arg("-c")
    .arg(script);
    let mut run = SpawnedRun::spawn(cmd);
    assert!(
        run.wait_for("SUP ", Duration::from_secs(30)),
        "target never reported its supervisor: {}",
        run.output()
    );
    let out = run.output();
    let tgt_pid: i32 = out
        .lines()
        .find_map(|l| l.strip_prefix("TGT ").and_then(|v| v.parse().ok()))
        .expect("target pid");
    let sup_pid: i32 = out
        .lines()
        .find_map(|l| l.strip_prefix("SUP ").and_then(|v| v.parse().ok()))
        .expect("supervisor pid");

    // Kill the supervisor like an external failure would.
    // SAFETY: kill with a positive pid only signals that process.
    let ret = unsafe { libc::kill(sup_pid, libc::SIGKILL) };
    assert_eq!(ret, 0, "kill supervisor");

    // The target must die (PDEATHSIG) and the run must terminate.
    let deadline = Instant::now() + Duration::from_secs(15);
    while pid_alive(tgt_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!pid_alive(tgt_pid), "target must die with the supervisor");

    let status = run
        .wait(Duration::from_secs(15))
        .expect("run must terminate after supervisor death");
    let code = status.code().unwrap_or(0);
    assert_eq!(
        code, 137,
        "supervisor death must surface as SIGKILL (137), got {code}"
    );
}

#[test]
fn early_supervisor_death_terminates_run() {
    // Supervisor death at any point of startup — before the wrapper
    // fork, in the ack window, or after — must never hang the run:
    // pre-ack deaths fail closed on socketpair EOF, post-ack deaths
    // cascade through PDEATHSIG. The regression this guards is the
    // orphaned-filter hang class.
    if !plain_supervisor_available() {
        eprintln!(
            "skipping: yama ptrace_scope={} denies the plain-run supervisor",
            yama_scope()
        );
        return;
    }
    let mut saw_supervisor_death = false;
    for _ in 0..5 {
        let mut cmd = Command::new(arapuca_bin());
        cmd.args([
            "run",
            "--seccomp",
            "baseline",
            "--deny-privileged-unix-sockets",
            "--",
        ])
        .arg("/bin/sh")
        .arg("-c")
        .arg("sleep 5");
        let mut run = SpawnedRun::spawn(cmd);
        let cli_pid = run.child.id();

        // Kill wave: every child of the CLI as it appears, for a
        // window that certainly covers the supervisor spawn and the
        // wrapper handover (check child, supervisor, wrapper).
        let wave_deadline = Instant::now() + Duration::from_millis(300);
        while Instant::now() < wave_deadline {
            for pid in children_of(cli_pid) {
                // SAFETY: kill with a positive pid only signals that process.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
            if let Ok(Some(_)) = run.child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }

        let status = run
            .wait(Duration::from_secs(20))
            .expect("run must terminate after early supervisor death");
        if status.code() == Some(137) {
            saw_supervisor_death = true;
        }
    }
    assert!(
        saw_supervisor_death,
        "kill wave must have reached the supervisor at least once"
    );
}

// ─── setsid semantics (group-leader design) ────────────────────

#[test]
fn target_setsid_fails_but_child_daemonizes() {
    // The wrapper is its own process-group leader, so the target
    // (same pid, exec'd in place) cannot setsid() — EPERM, the same
    // errno as the legacy session-leader topology. The escape would
    // let the target clear PDEATHSIG by daemonizing. Forked children
    // are not group leaders and must still setsid() successfully —
    // daemonization inside the sandbox keeps working.
    if !plain_supervisor_available() || !python3_available() {
        eprintln!("skipping: requires plain-run supervisor and python3");
        return;
    }
    let script = r#"
import errno, os
try:
    os.setsid()
    print("TARGET_SETSID_UNEXPECTED_OK")
except OSError as e:
    print("TARGET_SETSID_EPERM", e.errno == errno.EPERM)
pid = os.fork()
if pid == 0:
    try:
        os.setsid()
        # os.write, not print: the child exits via os._exit, which
        # skips buffer flushes — a buffered print would be lost on
        # the piped stdout and the oracle could never pass.
        os.write(1, b"CHILD_SETSID_OK\n")
    except OSError as e:
        os.write(1, b"CHILD_SETSID_EPERM %d\n" % e.errno)
    os._exit(0)
_, status = os.waitpid(pid, 0)
print("CHILD_STATUS", status)
"#;
    let out = Command::new(arapuca_bin())
        .args([
            "run",
            "--seccomp",
            "baseline",
            "--deny-privileged-unix-sockets",
            "--",
        ])
        .arg("python3")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("TARGET_SETSID_EPERM True"),
        "target setsid() must fail EPERM: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("CHILD_SETSID_OK"),
        "target child must daemonize: {stdout}"
    );
    assert!(
        stdout.contains("CHILD_STATUS 0"),
        "daemonized child must exit cleanly: {stdout}"
    );
}

// ─── pidns handover ────────────────────────────────────────────

#[test]
fn pidns_handover_through_supervisor() {
    // Netns launches imply a pid namespace: the wrapper's pidns child
    // installs the filter and the relay writes the pid-report. The
    // 8-byte pid+fd handover must reach the supervisor across that
    // topology, and the target must be pid 1 in its namespace.
    if !netns_supervisor_available() {
        eprintln!("skipping: requires userns/netns and yama scope < 3");
        return;
    }
    let out = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--deny-privileged-unix-sockets",
            "--",
        ])
        .arg("/bin/sh")
        .arg("-c")
        .arg("echo PIDNS_PID=$$; test $$ -eq 1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "pidns run through the supervisor must succeed: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("PIDNS_PID=1"),
        "target must be pid 1 in its namespace: {stdout}"
    );
}

// ─── Signaling through the pid-report ──────────────────────────

#[test]
fn timeout_sigterm_reaches_target_gracefully() {
    // Every supervisor-mode launch has a pid-report: the launcher's
    // pidfd targets the wrapper pid, not the supervisor. The graceful
    // timeout path must SIGTERM the target itself — a cascade
    // (supervisor death) would SIGKILL and the trap would never run.
    if !plain_supervisor_available() {
        eprintln!(
            "skipping: yama ptrace_scope={} denies the plain-run supervisor",
            yama_scope()
        );
        return;
    }
    let start = Instant::now();
    let out = Command::new(arapuca_bin())
        .args([
            "run",
            "--seccomp",
            "baseline",
            "--deny-privileged-unix-sockets",
            "--timeout",
            "2",
            "--",
        ])
        .arg("/bin/sh")
        .arg("-c")
        // `sleep & wait`: the trap must fire PROMPTLY. A foreground
        // `sleep 30` would defer the trap until the sleep exits
        // (bash runs traps between commands) — the grace-period
        // SIGKILL would always win and the oracle could never pass.
        // `wait` is interruptible by trapped signals.
        .arg(r#"trap 'echo TERM_HANDLED; exit 7' TERM; sleep 30 & wait"#)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("TERM_HANDLED"),
        "SIGTERM must reach the target's trap: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(7),
        "graceful shutdown exit code must propagate"
    );
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "timeout must fire promptly, took {:?}",
        start.elapsed()
    );
}

// ─── Concurrent sandboxes ──────────────────────────────────────

#[test]
fn concurrent_launches_do_not_interfere() {
    // Plain concurrent launches: fd accounting, pidfds, and — after
    // the rebase onto main's cleanup_stale fix — bystander safety:
    // no launch may disturb its siblings.
    const N: usize = 8;
    let mut handles = Vec::new();
    for i in 0..N {
        let bin = arapuca_bin();
        handles.push(std::thread::spawn(move || {
            Command::new(bin)
                .args([
                    "run",
                    "--seccomp",
                    "baseline",
                    "--task-id",
                    &format!("conc-plain-{i}"),
                    "--",
                ])
                .arg("/bin/sh")
                .arg("-c")
                .arg(format!("echo plain-{i}"))
                .output()
                .unwrap()
        }));
    }
    for (i, handle) in handles.into_iter().enumerate() {
        let out = handle.join().expect("join");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains(&format!("plain-{i}")),
            "concurrent plain launch {i} failed: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Supervisor-mode concurrency: N unotify supervisors at once.
    if !plain_supervisor_available() {
        eprintln!(
            "skipping supervisor half: yama ptrace_scope={}",
            yama_scope()
        );
        return;
    }
    let mut handles = Vec::new();
    for i in 0..N {
        let bin = arapuca_bin();
        handles.push(std::thread::spawn(move || {
            Command::new(bin)
                .args([
                    "run",
                    "--seccomp",
                    "baseline",
                    "--deny-privileged-unix-sockets",
                    "--task-id",
                    &format!("conc-sup-{i}"),
                    "--",
                ])
                .arg("/bin/sh")
                .arg("-c")
                .arg(format!("echo sup-{i}"))
                .output()
                .unwrap()
        }));
    }
    for (i, handle) in handles.into_iter().enumerate() {
        let out = handle.join().expect("join");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains(&format!("sup-{i}")),
            "concurrent supervisor launch {i} failed: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

// ─── fd hygiene ────────────────────────────────────────────────

fn assert_target_fds_bounded(extra_args: &[&str]) {
    let mut cmd = Command::new(arapuca_bin());
    cmd.args(["run", "--seccomp", "baseline"])
        .args(extra_args)
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(r#"import os; print("FDS", sorted(int(f) for f in os.listdir("/proc/self/fd")))"#);
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "fd probe must succeed: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let fds: Vec<i32> = stdout
        .lines()
        .find_map(|l| l.strip_prefix("FDS ").map(|v| v.to_string()))
        .and_then(|v| {
            v.trim_matches(|c| c == '[' || c == ']')
                .replace(',', " ")
                .split_whitespace()
                .map(|n| n.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    // 0-2 = stdio; 3 may appear as the readdir artifact while
    // listdir(2) holds the directory open. Nothing else may leak.
    assert!(
        fds.iter().all(|fd| (0..=3).contains(fd)),
        "target must inherit only stdio (+ listing artifact), got {fds:?}: {stdout}"
    );
}

#[test]
fn inherited_target_fds_are_bounded_plain() {
    if !python3_available() {
        eprintln!("skipping: requires python3");
        return;
    }
    assert_target_fds_bounded(&[]);
}

#[test]
fn inherited_target_fds_are_bounded_supervisor() {
    if !python3_available() || !plain_supervisor_available() {
        eprintln!("skipping: requires python3 and plain-run supervisor");
        return;
    }
    assert_target_fds_bounded(&["--deny-privileged-unix-sockets"]);
}

// ─── Executable pinning (TOCTOU on the wrapper binary) ─────────

struct SwapRace {
    dir: tempfile::TempDir,
    bin: PathBuf,
    decoy: PathBuf,
    log: PathBuf,
}

impl SwapRace {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("arapuca");
        let orig = dir.path().join("orig-arapuca");
        let decoy = dir.path().join("decoy");
        let log = dir.path().join("decoy.log");
        std::fs::copy(arapuca_bin(), &orig).expect("copy binary");
        make_executable(&orig);
        // The decoy logs its first argument so the test can tell how
        // far it got: "--wrapper-capabilities" (pinned for the
        // capability check — harmless, retry), "run" (the test's own
        // spawn raced the swap — harmless, retry), "--supervisor" or
        // "--" (exec'd as supervisor/wrapper — the pin failed).
        std::fs::write(
            &decoy,
            format!("#!/bin/sh\necho \"$1\" >> {}\nexit 1\n", log.display()),
        )
        .expect("write decoy");
        make_executable(&decoy);
        // Place the real binary at the exec path.
        std::fs::hard_link(&orig, dir.path().join(".place")).unwrap();
        std::fs::rename(dir.path().join(".place"), &bin).unwrap();
        Self {
            dir,
            bin,
            decoy,
            log,
        }
    }

    /// Continuously swap the on-disk binary between the real one and
    /// the decoy until stopped. The pinned fd keeps the original
    /// inode alive regardless of the path's state, so every exec must
    /// keep hitting the real binary.
    fn start_swapper(&self) -> Arc<AtomicBool> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let decoy = self.decoy.clone();
        let bin = self.bin.clone();
        let orig_master = self.dir.path().join("orig-arapuca");
        std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                let staging = bin.parent().unwrap().join(".place");
                let _ = std::fs::remove_file(&staging);
                if std::fs::hard_link(&decoy, &staging).is_ok() {
                    let _ = std::fs::rename(&staging, &bin);
                }
                let staging = bin.parent().unwrap().join(".place");
                let _ = std::fs::remove_file(&staging);
                if std::fs::hard_link(&orig_master, &staging).is_ok() {
                    let _ = std::fs::rename(&staging, &bin);
                }
            }
        });
        stop
    }

    fn decoy_log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn clear_log(&self) {
        let _ = std::fs::remove_file(&self.log);
    }
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

/// Run `race` under a continuous binary swap. Requires
/// `required_clean` successful runs whose output came from the real
/// binary, with zero decoy executions of the supervisor/wrapper argv
/// shapes. Retries iterations where the decoy was pinned for the
/// capability check (a launch failure, not a policy failure).
fn swap_race_launch(args: &[&str], required_clean: usize, max_attempts: usize) {
    let race = SwapRace::new();
    let mut clean = 0;
    for attempt in 1..=max_attempts {
        race.clear_log();
        let mut cmd = Command::new(&race.bin);
        cmd.args(["run", "--seccomp", "baseline"])
            .args(args)
            .arg("--")
            .arg("/bin/sh")
            .arg("-c")
            .arg("echo swap-ok");
        let mut run = SpawnedRun::spawn(cmd);
        // Give the test's own execve time to land before swapping.
        std::thread::sleep(Duration::from_millis(5));
        let stop = race.start_swapper();
        let status = run.wait(Duration::from_secs(30)).expect("run terminates");
        stop.store(true, Ordering::Relaxed);
        let out = run.output();
        let log = race.decoy_log();

        for line in log.lines() {
            match line.trim() {
                // The decoy was pinned for the capability check, or
                // the test's own spawn raced a swap: launch failed
                // before any sandbox code ran. Retry.
                "--wrapper-capabilities" | "run" => {}
                // The decoy was exec'd as supervisor or wrapper: the
                // exec used the on-disk path instead of the pinned fd.
                "--supervisor" | "--" => {
                    panic!(
                        "decoy executed as {line:?} (attempt {attempt}): exec must use the pinned fd\noutput: {out}"
                    );
                }
                other => {
                    panic!("unexpected decoy invocation {other:?} (attempt {attempt})");
                }
            }
        }

        if status.success() && out.contains("swap-ok") {
            clean += 1;
            if clean >= required_clean {
                return;
            }
        }
        // A failed launch with an EMPTY decoy log is the swapper
        // overwriting the file while an exec was in flight: the
        // kernel read a half-written ELF and answered ENOEXEC before
        // any sandbox code ran — the same race class as the decoy
        // being pinned for the capability check, so retry it. The
        // final clean-run count is the backstop: a launch that never
        // succeeds still fails the test.
        if log.is_empty() && !status.success() {
            continue;
        }
    }
    panic!(
        "only {clean}/{required_clean} clean runs after {max_attempts} attempts \
         (check-phase collisions dominate — investigate)"
    );
}

#[test]
fn binary_swap_pinned_wrapper_exec_wins() {
    // The launcher pins the wrapper binary (fd 64+) and execs through
    // /proc/self/fd/N: a binary swapped on disk between the
    // capability check and the exec must never run. Works without a
    // supervisor (--no-unix-sockets pins the wrapper too).
    swap_race_launch(&["--no-unix-sockets"], 10, 60);
}

#[test]
fn binary_swap_pinned_supervisor_exec_wins() {
    // The supervisor-mode chain has two pinned execs: launcher →
    // supervisor and supervisor → wrapper (the inherited fd). Both
    // must survive the on-disk swap.
    if !plain_supervisor_available() {
        eprintln!(
            "skipping: yama ptrace_scope={} denies the plain-run supervisor",
            yama_scope()
        );
        return;
    }
    swap_race_launch(&["--deny-privileged-unix-sockets"], 5, 40);
}

// ─── Cgroup sync through the supervisor hop ────────────────────

#[test]
fn cgroup_limits_apply_through_supervisor() {
    // The supervisor consumes the cgroup-sync byte before forking the
    // wrapper, so the fork inherits membership: limits must bound the
    // wrapper tree, and the run must not hang on the sync byte.
    if !plain_supervisor_available() || !python3_available() || !cgroup_available() {
        eprintln!("skipping: requires supervisor, python3, and cgroup delegation");
        return;
    }
    let script = r#"
import os
cg = open("/proc/self/cgroup").read().strip()
print("CG", cg)
forks = 0
while forks < 40:
    try:
        pid = os.fork()
    except OSError:
        break
    if pid == 0:
        import time
        time.sleep(30)
        os._exit(0)
    forks += 1
print("FORKS", forks)
"#;
    let out = Command::new(arapuca_bin())
        .args([
            "run",
            "--seccomp",
            "baseline",
            "--deny-privileged-unix-sockets",
            "--memory",
            "256",
            "--pids",
            "8",
            "--task-id",
            "supcg",
            "--",
        ])
        .arg("python3")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "cgroup run through the supervisor must succeed: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("arapuca-supcg"),
        "wrapper tree must be inside the task cgroup: {stdout}"
    );
    let forks: usize = stdout
        .lines()
        .find_map(|l| l.strip_prefix("FORKS ").and_then(|v| v.parse().ok()))
        .unwrap_or(usize::MAX);
    // supervisor + wrapper + forks <= pids.max (8): at most 6 forks,
    // and at least one — the limit must bite, not merely exist.
    assert!(
        (1..=6).contains(&forks),
        "pids limit must bound the wrapper tree: {forks} forks\n{stdout}"
    );
}
#[test]
fn tty_ctrl_z_is_discarded_not_wedging_the_run() {
    // The wrapper's group is orphaned (its session leader's parent —
    // the supervisor — lives in another session), so the kernel
    // discards terminal stop signals for it. Before the session
    // shape was restored, the group was NOT orphaned: SIGTSTP from
    // Ctrl-Z stopped the target, nobody sent SIGCONT, and the run
    // hung until --timeout.
    if !plain_supervisor_available() {
        eprintln!("skipping: requires plain-run supervisor (Yama)");
        return;
    }
    let script = "echo READY; sleep 4; echo DONE";
    let (mut child, output, mut writer) = run_tty_target(script);
    let output_c = Arc::clone(&output);
    std::thread::spawn(move || {
        // Wait for READY, then send Ctrl-Z (VSTOP) into the pty.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if output_c.lock().unwrap().contains("READY") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // SAFETY-free: plain write of the stop character.
        use std::io::Write;
        let _ = writer.write_all(&[0x1a]);
        let _ = writer.flush();
    });
    // Bounded wait: a regression wedges the run, and the test must
    // fail on it, not hang the suite.
    let status = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => break status,
                None if std::time::Instant::now() > deadline => {
                    let _ = child.kill();
                    panic!("run wedged on Ctrl-Z (SIGTSTP stopped the target)");
                }
                None => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    };
    let out = output.lock().unwrap().clone();
    assert!(
        status.success() && out.contains("DONE"),
        "Ctrl-Z must be discarded (orphaned group), not stop the run: \
         status={status:?} output={out:?}"
    );
}
