//! Integration tests for `arapuca run` subcommand.
//!
//! Tests exercise the binary via std::process::Command. Requires
//! Linux with Landlock (5.13+) for sandbox enforcement.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

fn arapuca_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove "deps"
    path.push("arapuca");
    path
}

// ─── Security property tests ─────────────────────────────────

#[test]
fn path_confinement_blocks_unallowed_reads() {
    // Create the file outside /tmp (which is a default write path).
    // Use the current directory (repo root) which is NOT in defaults.
    let dir = tempfile::Builder::new()
        .prefix("arapuca-confinement-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, "classified").unwrap();

    let output = Command::new(arapuca_bin())
        .args(["run", "--", "/bin/cat"])
        .arg(&secret)
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "cat should fail on path outside allow list"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Permission denied") || stderr.contains("denied"),
        "expected permission denied, got: {stderr}"
    );
}

#[test]
fn read_only_enforcement() {
    // Use a directory outside defaults so the :ro flag is the only
    // access grant. /tmp is a default write path so it can't be used.
    let dir = tempfile::Builder::new()
        .prefix("arapuca-ro-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let dir_str = dir.path().to_str().unwrap();
    let vol = format!("{dir_str}:ro");

    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "-v",
            &vol,
            "--",
            "/bin/sh",
            "-c",
            &format!("touch {dir_str}/test-write"),
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "write to read-only path should fail"
    );
}

#[test]
fn default_paths_sufficient_for_basic_commands() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--", "/bin/true"])
        .status()
        .unwrap();

    assert!(status.success(), "/bin/true should succeed with defaults");
}

#[test]
fn allow_network_listeners_confines_tcp_to_netns_loopback() {
    if !arapuca::netns::available() {
        eprintln!("skipping listener namespace test: unprivileged netns unavailable");
        return;
    }

    let test_binary = std::env::current_exe().unwrap();
    let test_binary_dir = test_binary.parent().unwrap();
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--allow-network-listeners",
            "-v",
            &format!("{}:ro", test_binary_dir.display()),
            "--env",
            "ARKAI_ARAPUCA_TEST_LISTENER_HELPER=1",
            "--",
        ])
        .arg(&test_binary)
        .args(["--exact", "network_listener_helper", "--nocapture"])
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
fn network_listener_helper() {
    if std::env::var_os("ARKAI_ARAPUCA_TEST_LISTENER_HELPER").is_none() {
        return;
    }

    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("namespace loopback should work");
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .expect("namespace loopback connect should work");
    let (accepted, _) = listener
        .accept()
        .expect("namespace loopback accept should work");
    drop((client, accepted));

    let external = TcpStream::connect_timeout(
        &"203.0.113.1:443".parse().unwrap(),
        Duration::from_millis(250),
    );
    assert!(external.is_err(), "external egress must remain isolated");
}

// ─── Functional tests ────────────────────────────────────────

#[test]
fn exit_code_nonzero() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--", "/bin/false"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
}

#[test]
fn path_access_with_volume() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.txt");
    std::fs::write(&file, "hello from volume").unwrap();

    let dir_str = dir.path().to_str().unwrap();
    let vol = format!("{dir_str}:ro");

    let output = Command::new(arapuca_bin())
        .args(["run", "-v", &vol, "--", "/bin/cat"])
        .arg(&file)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "cat should succeed on allowed path"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello from volume"
    );
}

#[test]
fn combined_env_filtering() {
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--env",
            "MY_SAFE_VAR=present",
            "--env",
            "CUSTOM_TOKEN=secret123",
            "--",
            "/bin/sh",
            "-c",
            "echo safe=$MY_SAFE_VAR token=$CUSTOM_TOKEN ld=${LD_PRELOAD:-unset}",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("safe=present"),
        "safe var should be passed: {stdout}"
    );
    assert!(
        stdout.contains("token=secret123"),
        "custom token should be passed: {stdout}"
    );
    assert!(
        stdout.contains("ld=unset"),
        "LD_PRELOAD should not leak from host: {stdout}"
    );
}

#[test]
fn exec_chain_through_seccomp() {
    let output = Command::new(arapuca_bin())
        .args(["run", "--", "/bin/sh", "-c", "/bin/echo exec-ok"])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "exec-ok");
}

#[test]
fn timeout_kills_process() {
    let start = std::time::Instant::now();
    let status = Command::new(arapuca_bin())
        .args(["run", "--timeout", "2", "--", "/bin/sleep", "60"])
        .status()
        .unwrap();
    let elapsed = start.elapsed();

    assert!(!status.success(), "sleep should have been killed");

    // Exit code should be 128 + signal (SIGTERM=15 → 143, SIGKILL=9 → 137).
    let code = status.code().unwrap_or(0);
    assert!(
        code == 137 || code == 143,
        "expected exit code 137 or 143, got {code}"
    );

    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "timeout should have fired within ~7s, took {elapsed:?}"
    );
}

#[test]
fn timeout_fast_exit_no_delay() {
    let start = std::time::Instant::now();
    let status = Command::new(arapuca_bin())
        .args(["run", "--timeout", "30", "--", "/bin/true"])
        .status()
        .unwrap();
    let elapsed = start.elapsed();

    assert!(status.success());
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "fast exit should not wait for timeout, took {elapsed:?}"
    );
}

fn cgroup_available() -> bool {
    Command::new(arapuca_bin())
        .args(["run", "--memory", "256", "--", "/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn resource_limits_flag_accepted() {
    if !cgroup_available() {
        eprintln!("skipping: cgroups not available");
        return;
    }
    let status = Command::new(arapuca_bin())
        .args([
            "run",
            "--memory",
            "256",
            "--cpus",
            "200",
            "--pids",
            "100",
            "--",
            "/bin/true",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

// ─── Error handling tests ────────────────────────────────────

#[test]
fn unknown_flag_exits_125() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--bogus", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn no_command_exits_125() {
    let status = Command::new(arapuca_bin()).args(["run"]).status().unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn missing_separator_shows_hint() {
    let output = Command::new(arapuca_bin())
        .args(["run", "/bin/ls"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("did you forget"),
        "should show hint about missing '--': {stderr}"
    );
}

#[test]
fn env_override_sandbox_managed_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--env", "HOME=/evil", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "overriding HOME should be rejected"
    );
}

// ─── Env injection tests ─────────────────────────────────────

#[test]
fn env_dangerous_var_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--env", "LD_PRELOAD=/evil.so", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "LD_PRELOAD should be rejected at CLI layer"
    );
}

#[test]
fn env_arapuca_prefix_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--env", "ARAPUCA_READ_PATHS=/", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "ARAPUCA_* vars should be rejected at CLI layer"
    );
}

#[test]
fn env_interpreter_injection_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--env", "BASH_ENV=/evil", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "BASH_ENV should be rejected at CLI layer"
    );
}

// ─── Validation edge case tests ──────────────────────────────

#[test]
fn volume_relative_path_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "-v", "relative/path", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn volume_empty_path_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "-v", ":ro", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn task_id_traversal_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--task-id", "../../etc", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn timeout_zero_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--timeout", "0", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn env_without_value_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--env", "NOVALUE", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

// ─── --allow-host tests ──────────────────────────────────────

#[test]
fn allow_host_invalid_format_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--allow-host", "noport", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn allow_host_port_zero_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--allow-host", "host:0", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn allow_host_invalid_hostname_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--allow-host", "bad host:443", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn allow_host_consecutive_dots_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--allow-host", "host..com:443", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn allow_host_port_overflow_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--allow-host", "host:65536", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn allow_host_wildcard_accepted() {
    // *.domain:port should be accepted as a valid wildcard.
    // We can't test the actual proxy tunnel without netns, but
    // we can verify the flag parses without error by checking
    // that it doesn't exit 125 (validation errors).
    // If netns is unavailable, the sandbox launch may fail, but
    // the flag parsing itself should succeed.
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--allow-host",
            "*.googleapis.com:443",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("invalid"),
        "wildcard --allow-host should be accepted: {stderr}"
    );
}

#[test]
fn allow_host_wildcard_empty_domain_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--allow-host", "*.:443", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn allow_host_bare_star_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--allow-host", "*:443", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn allow_host_double_star_rejected() {
    let status = Command::new(arapuca_bin())
        .args([
            "run",
            "--allow-host",
            "**.example.com:443",
            "--",
            "/bin/true",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn no_allow_host_does_not_set_proxy() {
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--",
            "/bin/sh",
            "-c",
            "echo proxy=${HTTPS_PROXY:-unset}",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("proxy=unset"),
        "HTTPS_PROXY should not be set without --allow-host: {stdout}"
    );
}

fn netns_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--net", "--map-current-user", "--", "/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn allow_host_sets_https_proxy() {
    if !netns_available() {
        eprintln!("skipping: netns not available");
        return;
    }
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--allow-host",
            "example.com:443",
            "--",
            "/bin/sh",
            "-c",
            "echo proxy=${HTTPS_PROXY:-unset}",
        ])
        .output()
        .unwrap();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("loopback") || stderr.contains("Operation not permitted") {
            eprintln!("skipping: netns not functional: {stderr}");
            return;
        }
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("http://127.0.0.1:"),
        "HTTPS_PROXY should be set with --allow-host: {stdout}"
    );
}

// ─── Seccomp profile tests ───────────────────────────────────

#[test]
fn seccomp_baseline_runs_successfully() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--seccomp", "baseline", "--", "/bin/true"])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn seccomp_strict_runs_successfully() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--seccomp", "strict", "--", "/bin/true"])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn seccomp_invalid_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--seccomp", "bogus", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(125));
}

#[test]
fn seccomp_baseline_includes_proc_sys() {
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--seccomp",
            "baseline",
            "--",
            "/bin/sh",
            "-c",
            "test -r /proc/self/cgroup && echo proc_ok || echo proc_fail",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("proc_ok"),
        "baseline should grant /proc access: {stdout}"
    );
}

#[test]
fn seccomp_strict_blocks_network_socket() {
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--seccomp",
            "strict",
            "--",
            "/bin/sh",
            "-c",
            "python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)' 2>&1; echo exit=$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Operation not permitted")
            || combined.contains("EPERM")
            || combined.contains("exit=1"),
        "strict should block AF_INET: {combined}"
    );
}

#[test]
fn seccomp_baseline_allows_network_socket() {
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--seccomp",
            "baseline",
            "--",
            "/bin/sh",
            "-c",
            "python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); print(\"INET_OK\")' 2>&1",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("INET_OK"),
        "baseline should allow AF_INET: {stdout}"
    );
}

#[test]
fn seccomp_baseline_blocks_ptrace() {
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--seccomp",
            "baseline",
            "--",
            "/bin/sh",
            "-c",
            "strace -e trace=none /bin/true 2>&1; echo exit=$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("exit=159") || stdout.contains("exit=137"),
        "baseline should block ptrace (strace): {stdout}"
    );
}

#[test]
fn seccomp_strict_blocks_proc_read() {
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--seccomp",
            "strict",
            "--",
            "/bin/sh",
            "-c",
            "cat /proc/self/cgroup 2>&1 && echo proc_ok || echo proc_fail",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("proc_fail") || stdout.contains("Permission denied"),
        "strict should block /proc reads: {stdout}"
    );
}

// ─── PTY mode tests ──────────────────────────────────────────

#[test]
fn tty_flag_requires_terminal_stdin() {
    let output = Command::new(arapuca_bin())
        .args(["run", "-t", "--", "/bin/true"])
        .stdin(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(125),
        "-t with piped stdin should exit 125"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("terminal"),
        "should mention terminal requirement: {stderr}"
    );
}

#[test]
fn tty_long_flag_works() {
    let output = Command::new(arapuca_bin())
        .args(["run", "--tty", "--", "/bin/true"])
        .stdin(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(125),
        "--tty with piped stdin should exit 125"
    );
}

// ─── PTY I/O loop tests ───────────────────────────────────────
//
// These require a real PTY via script(1). Skipped if script is
// not available or cannot allocate a PTY.

fn pty_available() -> bool {
    script_command("/bin/true")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Build a `script(1)` command that works on both GNU (Linux) and
/// BSD (macOS). GNU: `script -q -c 'cmd' /dev/null`. BSD: `script
/// -q /dev/null cmd`.
fn script_command(inner_cmd: &str) -> Command {
    let mut cmd = Command::new("script");
    if cfg!(target_os = "linux") {
        cmd.args(["-q", "-c", inner_cmd, "/dev/null"]);
    } else {
        // BSD/macOS: script -q /dev/null <shell> -c <cmd>
        cmd.args(["-q", "/dev/null", "/bin/sh", "-c", inner_cmd]);
    }
    cmd
}

#[test]
fn pty_bidirectional_io_no_deadlock() {
    if !pty_available() {
        eprintln!("skipping: script(1) not available for PTY allocation");
        return;
    }

    let arapuca = arapuca_bin();
    let inner = format!(
        "{} run --seccomp baseline -t -- /bin/sh -c \
         'dd if=/dev/zero bs=4096 count=16 2>/dev/null; echo PTY_IO_OK'",
        arapuca.display()
    );
    let mut child = script_command(&inner)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let result = wait_with_timeout(&mut child, std::time::Duration::from_secs(15));
    match result {
        Some(status) => {
            let stdout = {
                let mut buf = String::new();
                if let Some(mut out) = child.stdout.take() {
                    use std::io::Read;
                    let _ = out.read_to_string(&mut buf);
                }
                buf
            };
            let clean = stdout.replace('\r', "");
            assert!(
                clean.contains("PTY_IO_OK"),
                "PTY I/O should complete without deadlock: {clean}"
            );
            assert!(status.success(), "should exit 0, got {:?}", status.code());
        }
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("PTY I/O deadlock: timed out after 15 seconds");
        }
    }
}

/// Wait for a child process with a timeout. Returns None on timeout.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: std::time::Duration,
) -> Option<std::process::ExitStatus> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if start.elapsed() > timeout {
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(_) => return None,
        }
    }
}

// ─── --cwd tests ─────────────────────────────────────────────

#[test]
fn cwd_sets_working_directory() {
    let dir = tempfile::tempdir().unwrap();
    let canonical = dir.path().canonicalize().unwrap();
    let canonical_str = canonical.to_str().unwrap();
    let vol = format!("{canonical_str}:ro");

    let output = Command::new(arapuca_bin())
        .args(["run", "--cwd", canonical_str, "-v", &vol, "--", "/bin/pwd"])
        .output()
        .unwrap();

    assert!(output.status.success(), "pwd should succeed with --cwd");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        canonical_str,
        "working directory should match --cwd"
    );
}

#[test]
fn cwd_without_mount_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--cwd", "/opt", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "--cwd without matching mount should exit 125"
    );
}

#[test]
fn cwd_relative_path_rejected() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--cwd", "./relative", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "--cwd with relative path should exit 125"
    );
}

#[test]
fn cwd_nonexistent_path_rejected() {
    let status = Command::new(arapuca_bin())
        .args([
            "run",
            "--cwd",
            "/nonexistent-arapuca-test-path",
            "-v",
            "/nonexistent-arapuca-test-path:ro",
            "--",
            "/bin/true",
        ])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "--cwd with nonexistent path should exit 125"
    );
}

#[test]
fn cwd_symlink_outside_mount_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("escape");
    std::os::unix::fs::symlink("/etc", &link).unwrap();

    let canonical = dir.path().canonicalize().unwrap();
    let dir_str = canonical.to_str().unwrap();
    let vol = format!("{dir_str}:ro");
    let link_str = link.to_str().unwrap();

    let status = Command::new(arapuca_bin())
        .args(["run", "--cwd", link_str, "-v", &vol, "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "--cwd symlink pointing outside mount should exit 125"
    );
}

#[test]
fn cwd_file_not_directory_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("not-a-dir.txt");
    std::fs::write(&file, "").unwrap();

    let canonical = dir.path().canonicalize().unwrap();
    let dir_str = canonical.to_str().unwrap();
    let vol = format!("{dir_str}:ro");
    let file_str = file.to_str().unwrap();

    let status = Command::new(arapuca_bin())
        .args(["run", "--cwd", file_str, "-v", &vol, "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "--cwd pointing to a file should exit 125"
    );
}

#[test]
fn cwd_tmp_rejected_without_explicit_grant() {
    // /tmp is intentionally NOT a default read path (host-shared temp
    // dirs must not be visible unless explicitly granted via -v).
    let status = Command::new(arapuca_bin())
        .args(["run", "--cwd", "/tmp", "--", "/bin/pwd"])
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "--cwd /tmp should be rejected without an explicit -v grant"
    );
}

#[test]
fn cwd_tmp_with_explicit_grant() {
    let expected = std::path::PathBuf::from("/tmp").canonicalize().unwrap();
    let expected_str = expected.to_str().unwrap();

    let output = Command::new(arapuca_bin())
        .args(["run", "--cwd", "/tmp", "-v", "/tmp", "--", "/bin/pwd"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "--cwd /tmp should work once /tmp is explicitly granted via -v"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        expected_str,
        "working directory should be /tmp (canonicalized)"
    );
}

#[test]
fn cwd_subdirectory_of_mount_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("child");
    std::fs::create_dir(&sub).unwrap();

    let canonical_dir = dir.path().canonicalize().unwrap();
    let canonical_sub = sub.canonicalize().unwrap();
    let dir_str = canonical_dir.to_str().unwrap();
    let sub_str = canonical_sub.to_str().unwrap();
    let vol = format!("{dir_str}:ro");

    let output = Command::new(arapuca_bin())
        .args(["run", "--cwd", sub_str, "-v", &vol, "--", "/bin/pwd"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "--cwd subdirectory of mount should succeed"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        sub_str,
        "working directory should match --cwd subdirectory"
    );
}

#[test]
fn cwd_path_traversal_resolved() {
    let status = Command::new(arapuca_bin())
        .args(["run", "--cwd", "/tmp/../etc", "--", "/bin/true"])
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(125),
        "--cwd with path traversal should resolve and be rejected"
    );
}

#[test]
fn cwd_with_write_mount_allows_writing() {
    let dir = tempfile::tempdir().unwrap();
    let canonical = dir.path().canonicalize().unwrap();
    let dir_str = canonical.to_str().unwrap();

    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--cwd",
            dir_str,
            "-v",
            dir_str,
            "--",
            "/bin/sh",
            "-c",
            "echo ok > testfile && cat testfile",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "--cwd with rw mount should allow writes"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "ok",
        "write to cwd should succeed with rw mount"
    );
}

// ─── /tmp write restriction tests ─────────────────────────────

#[test]
fn private_tmpdir_writable_but_slash_tmp_blocked() {
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--",
            "/bin/sh",
            "-c",
            "touch \"$TMPDIR/ok\" && echo TMPDIR_OK; \
             touch /tmp/arapuca-tmp-test-fail 2>/dev/null && echo TMP_WRITABLE || echo TMP_BLOCKED",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("TMPDIR_OK"),
        "private temp dir should be writable: {stdout}"
    );
    assert!(
        stdout.contains("TMP_BLOCKED"),
        "/tmp should be read-only by default: {stdout}"
    );
}

// ─── --deny-network tests ─────────────────────────────────────

fn netns_root_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--net", "--map-root-user", "--", "/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn deny_network_resolv_conf_override() {
    if !netns_root_available() {
        eprintln!("skipping: unshare --user --net --map-root-user not available");
        return;
    }
    let output = Command::new("unshare")
        .args(["--user", "--net", "--mount", "--map-root-user", "--"])
        .arg(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/sh",
            "-c",
            "cat /etc/resolv.conf",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "deny-network should succeed (exit {:?}):\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code(),
    );
    assert!(
        stdout.contains("nameserver 127.0.0.1"),
        "resolv.conf should be overridden to 127.0.0.1, got: {stdout}"
    );
}

#[test]
fn deny_network_dns_nxdomain() {
    if !netns_root_available() {
        eprintln!("skipping: unshare --user --net --map-root-user not available");
        return;
    }
    if Command::new("nslookup")
        .arg("-version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("skipping: nslookup not available");
        return;
    }
    let output = Command::new("unshare")
        .args(["--user", "--net", "--mount", "--map-root-user", "--"])
        .arg(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--seccomp",
            "baseline",
            "--",
            "/bin/sh",
            "-c",
            "nslookup example.com 2>&1; true",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "deny-network should succeed (exit {:?}):\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code(),
    );
    assert!(
        stdout.contains("NXDOMAIN") || stdout.contains("server can't find"),
        "DNS query should get NXDOMAIN, got: {stdout}"
    );
}

#[test]
fn deny_network_with_allow_host_rejected() {
    let output = Command::new(arapuca_bin())
        .args([
            "run",
            "--deny-network",
            "--allow-host",
            "example.com:443",
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("mutually exclusive"),
        "should reject combination, got: {stderr}"
    );
}
