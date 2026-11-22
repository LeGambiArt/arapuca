//! Helper hardening oracle: every arapuca helper process inside a
//! sandboxed launch must be unable to become a memory-corruption
//! pivot for the target.
//!
//! The sandboxed wrapper forks helpers (pidns relay, bridge, and the
//! unotify supervisor) that live in the same user namespace as the
//! target. A capful helper without its own seccomp allowlist is a
//! pivot: capabilities bypass `PR_SET_DUMPABLE=0` and Yama, so
//! anything that can open its `/proc/<pid>/mem` controls it.
//!
//! The scan runs from the test process, walking the launcher's
//! descendant tree. An earlier version of this oracle scanned
//! target-side for helpers as *children of the target*, which can
//! never exist in the parent topology (the relay is the target's
//! parent and the bridge its sibling), and it compared the pidns pid
//! against host `/proc` pids. It found nothing and failed.
//!
//! Two properties make this oracle non-vacuous:
//! - a positive control asserts the scan actually sees capful arapuca
//!   processes (the launcher under `--map-root-user`), so a
//!   "everyone is capless" result cannot come from a broken read;
//! - the expected roles are enumerated structurally (argv plus ppid),
//!   not by the 15-byte `comm` a target could set for itself.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn arapuca_bin() -> PathBuf {
    // Compile-time location of the binary built by this package:
    // robust to cargo's test-binary layout (deps/ vs build/out/),
    // which differs across cargo versions.
    PathBuf::from(env!("CARGO_BIN_EXE_arapuca"))
}

fn netns_root_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--net", "--map-root-user", "--", "/bin/true"])
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

fn yama_scope_is_absolute() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().parse::<u32>().unwrap_or(0) >= 3)
        .unwrap_or(false)
}

/// One snapshot of the fields the oracle needs, read in a single pass.
#[derive(Debug, Clone)]
struct ProcInfo {
    pid: i32,
    ppid: i32,
    starttime: u64,
    argv: String,
    exe: String,
    cap_eff: u64,
    seccomp: u8,
    no_new_privs: u8,
}

/// Read `/proc/<pid>` once. `None` means the process is gone.
fn read_proc(pid: i32) -> Option<ProcInfo> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after the comm (which may contain spaces and parens):
    //   state ppid ... starttime is field 22 overall.
    let after = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after.split_whitespace().collect();
    let ppid: i32 = fields.get(1)?.parse().ok()?;
    let starttime: u64 = fields.get(19)?.parse().ok()?;

    let argv = std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
        .unwrap_or_default();

    // The supervisor is exec'd through the pinned descriptor, so argv[0]
    // reads `/proc/self/fd/N`; the executable link is the structural way
    // to tell an arapuca helper from the sandboxed target.
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut cap_eff = 0u64;
    let mut seccomp = 0u8;
    let mut no_new_privs = 0u8;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("CapEff:") {
            cap_eff = u64::from_str_radix(v.trim(), 16).unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("Seccomp:") {
            seccomp = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("NoNewPrivs:") {
            no_new_privs = v.trim().parse().unwrap_or(0);
        }
    }
    Some(ProcInfo {
        pid,
        ppid,
        starttime,
        argv,
        exe,
        cap_eff,
        seccomp,
        no_new_privs,
    })
}

/// Collect the descendants of `root` that are arapuca processes.
fn arapuca_tree(root: i32) -> Vec<ProcInfo> {
    let me = std::fs::canonicalize(arapuca_bin()).unwrap_or_else(|_| arapuca_bin());
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    let mut all: HashMap<i32, ProcInfo> = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        if let Some(info) = read_proc(pid) {
            children.entry(info.ppid).or_default().push(pid);
            all.insert(pid, info);
        }
    }

    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(pid) = stack.pop() {
        for &child in children.get(&pid).map(Vec::as_slice).unwrap_or(&[]) {
            if let Some(info) = all.get(&child) {
                let is_arapuca = std::fs::canonicalize(&info.exe)
                    .map(|p| p == me)
                    .unwrap_or(false);
                if is_arapuca {
                    out.push(info.clone());
                }
            }
            stack.push(child);
        }
    }
    out
}

/// Classify a helper role structurally. `None` is the launcher itself.
fn role_of(info: &ProcInfo) -> Option<&'static str> {
    if info.argv.contains("--supervisor") {
        Some("supervisor")
    } else if info.argv.contains("-- ") || info.argv.ends_with("--") {
        // The wrapper is exec'd as `arapuca -- <target> ...`.
        Some("wrapper")
    } else {
        None
    }
}

/// Assert the hardening predicate once the tree has settled.
///
/// The supervisor installs its seccomp filter and NNP after forking
/// and after a blocking cgroup-sync read, and the bridge/relay harden
/// inside fork children that may not have been scheduled yet, so a
/// single immediate snapshot races the launch. Retry with a bound;
/// fail with the last observation instead of skipping.
fn assert_hardened(launcher_pid: i32) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let tree = arapuca_tree(launcher_pid);
        let mut problems = Vec::new();
        let mut seen_supervisor = false;
        let mut seen_wrapper = false;

        for info in &tree {
            // A process that exited between the /proc reads must not be
            // judged on a torn snapshot.
            let still_there =
                read_proc(info.pid).is_some_and(|now| now.starttime == info.starttime);
            if !still_there {
                problems.push(format!("{} vanished mid-scan", info.pid));
                continue;
            }
            match role_of(info) {
                Some("supervisor") => {
                    seen_supervisor = true;
                    // Keeps capabilities by design (it must inspect the
                    // target at Yama scope 2); the allowlist and
                    // dumpable=0 are what contain it.
                    if info.seccomp != 2 {
                        problems.push(format!("supervisor {} has no seccomp allowlist", info.pid));
                    }
                    if info.no_new_privs != 1 {
                        problems.push(format!("supervisor {} lacks NNP", info.pid));
                    }
                }
                Some(_) => {
                    seen_wrapper = true;
                    if info.cap_eff != 0 {
                        problems.push(format!(
                            "helper {} keeps capabilities: {:#x} ({})",
                            info.pid, info.cap_eff, info.argv
                        ));
                    }
                    if info.no_new_privs != 1 {
                        problems.push(format!("helper {} lacks NNP", info.pid));
                    }
                }
                None => {}
            }
        }

        if !problems.is_empty() {
            if Instant::now() >= deadline {
                return Err(format!("helpers never hardened: {}", problems.join("; ")));
            }
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        if !seen_supervisor || !seen_wrapper {
            if Instant::now() >= deadline {
                return Err(format!(
                    "could not locate every expected helper (supervisor={seen_supervisor}, \
                     wrapper={seen_wrapper}): {:?}",
                    tree.iter()
                        .map(|i| (&i.argv, i.cap_eff))
                        .collect::<Vec<_>>()
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        return Ok(());
    }
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn helpers_never_pivot_from_inside_the_sandbox() {
    if !netns_root_available() || !python3_available() {
        eprintln!("skipping: requires unshare userns and python3");
        return;
    }
    if yama_scope_is_absolute() {
        eprintln!("skipping: yama ptrace_scope=3 denies the supervisor inspection");
        return;
    }

    // A sleeping target keeps the whole helper tree alive while the
    // oracle scans it. `--deny-privileged-unix-sockets` is what spawns
    // the supervisor; `--deny-network` provides the user+network
    // namespace and the pidns relay.
    let child = Command::new("unshare")
        .args(["--user", "--net", "--map-root-user", "--"])
        .arg(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--deny-privileged-unix-sockets",
            "--seccomp",
            "baseline",
            "--",
            "/bin/sh",
            "-c",
            "sleep 20",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sandboxed launch");
    let guard = KillOnDrop(child);
    let launcher = guard.0.id() as i32;

    // Positive control: the scan must be able to see a capful process,
    // otherwise "everybody is capless" proves nothing. Under
    // `--map-root-user` the launcher holds the full user-namespace
    // capability set.
    let mut capful_seen = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(info) = read_proc(launcher) {
            if info.cap_eff != 0 {
                capful_seen = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        capful_seen,
        "positive control failed: the scan never observed a capful arapuca process, \
         so a capless result below would be vacuous"
    );

    if let Err(e) = assert_hardened(launcher) {
        panic!("{e}");
    }
}
