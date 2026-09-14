//! macOS Seatbelt integration tests.
//!
//! Exercises the darwin sandbox-exec launch chain end-to-end:
//! profile generation, path canonicalization, pipe FD inheritance,
//! and Seatbelt enforcement of deny-default policy.
//!
//! Requires macOS with `sandbox-exec` available.
#![cfg(target_os = "macos")]

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs as unix_fs;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;

use arapuca::platform::{Sandbox, new};
use arapuca::{Config, Profile};

fn pipe_pair() -> (File, File) {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(ret, 0, "pipe() failed");
    for &fd in &fds {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "fcntl F_GETFD failed");
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        assert!(ret >= 0, "fcntl F_SETFD CLOEXEC failed");
    }
    unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
}

fn base_config(task_id: &str) -> Config {
    Config {
        profile: Profile::default(),
        socket_dir: PathBuf::new(),
        task_id: task_id.into(),
        phase: "test".into(),
        work_dir: None,
        stdin: None,
        stdout: None,
        stderr: None,
        extra_fds: Vec::new(),
        tty: false,
        network_proxy_socket: None,
        env: Vec::new(),
        audit_sink: None,
        audit_verbosity: arapuca::audit::AuditVerbosity::Standard,
        audit_principal: None,
        audit_correlation_id: None,
    }
}

// ── Smoke tests ────────────────────────────────────────────────

/// Basic launch through sandbox-exec: capture stdout from /bin/echo.
///
/// Implicitly covers:
/// - Bug #2 (empty socket_dir): base_config uses PathBuf::new()
/// - Bug #3 (dyld bootstrap): without the (literal "/") fix, the
///   process would SIGABRT before producing output
#[test]
fn seatbelt_echo_stdout() {
    let (stdout_r, stdout_w) = pipe_pair();
    let (_stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config("darwin-echo");
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/echo", &["hello"]).unwrap();

    drop(stdout_w);
    drop(stderr_w);

    let mut stdout = String::new();
    stdout_r.take(4096).read_to_string(&mut stdout).unwrap();

    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(status.success(), "echo should exit 0");
    assert_eq!(stdout.trim(), "hello");
}

/// stdin→stdout relay via /bin/cat through sandbox-exec.
/// Proves bidirectional pipe FD inheritance survives the wrapper.
#[test]
fn seatbelt_stdin_stdout_relay() {
    let (stdin_r, mut stdin_w) = pipe_pair();
    let (stdout_r, stdout_w) = pipe_pair();
    let (_stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config("darwin-relay");
    cfg.stdin = Some(stdin_r.as_raw_fd());
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/cat", &[]).unwrap();

    drop(stdin_r);
    drop(stdout_w);
    drop(stderr_w);

    stdin_w.write_all(b"relay-test\n").unwrap();
    drop(stdin_w);

    let mut stdout = String::new();
    stdout_r.take(4096).read_to_string(&mut stdout).unwrap();

    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(status.success(), "cat should exit 0");
    assert_eq!(stdout.trim(), "relay-test");
}

// ── Regression tests ───────────────────────────────────────────

/// Regression for bug #4: symlinked cmd path must be canonicalized.
///
/// Creates a shell script in one temp dir and a symlink to it in
/// another. The profile's exec_paths will contain the canonical
/// (real) dir. Without the cmd canonicalization fix, Seatbelt
/// denies exec because the symlink path doesn't match.
///
/// Uses a shell script instead of copying /bin/echo because macOS
/// code signing enforcement kills copied system binaries.
///
/// CRITICAL: must NOT use /bin/echo directly — /bin is a hardcoded
/// system exec path and would pass regardless of the fix.
#[test]
fn seatbelt_symlink_cmd_resolves() {
    let real_dir = tempfile::tempdir().unwrap();
    let link_dir = tempfile::tempdir().unwrap();

    let real_path = fs::canonicalize(real_dir.path()).unwrap();
    let link_path = fs::canonicalize(link_dir.path()).unwrap();

    let real_script = real_path.join("test-echo.sh");
    fs::write(&real_script, "#!/bin/sh\necho symlink-ok\n").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&real_script, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let link_script = link_path.join("test-echo-link");
    unix_fs::symlink(&real_script, &link_script).unwrap();

    let (stdout_r, stdout_w) = pipe_pair();
    let (stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config("darwin-symlink");
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());
    cfg.profile.read_paths = vec![real_path.clone(), link_path.clone()];

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, link_script.to_str().unwrap(), &[]).unwrap();

    drop(stdout_w);
    drop(stderr_w);

    let mut stdout = String::new();
    stdout_r.take(4096).read_to_string(&mut stdout).unwrap();

    let mut stderr = String::new();
    stderr_r.take(4096).read_to_string(&mut stderr).unwrap();

    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(
        status.success(),
        "symlinked cmd should resolve and exec successfully, \
         exit={:?}, stdout={stdout:?}, stderr={stderr:?}",
        status.code()
    );
    assert_eq!(stdout.trim(), "symlink-ok");
}

/// Regression for bug #1: `@` in paths must be accepted.
///
/// Creates a temp dir with `@` in the name, places a file there,
/// and reads it through the sandbox. Proves `@` flows through
/// profile validation, generation, and sandbox-exec.
#[test]
fn seatbelt_at_sign_in_path() {
    let parent = tempfile::tempdir().unwrap();
    // Canonicalize so Seatbelt path matching works on macOS
    // where /var -> /private/var.
    let parent_canon = fs::canonicalize(parent.path()).unwrap();
    let at_dir = parent_canon.join("test-python@3.14");
    fs::create_dir(&at_dir).unwrap();

    let test_file = at_dir.join("marker.txt");
    fs::write(&test_file, "at-sign-ok\n").unwrap();

    let (stdout_r, stdout_w) = pipe_pair();
    let (stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config("darwin-atsign");
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());
    cfg.profile.read_paths = vec![at_dir.clone()];

    let sb = new().unwrap();
    let mut proc = sb
        .launch(&cfg, "/bin/cat", &[test_file.to_str().unwrap()])
        .unwrap();

    drop(stdout_w);
    drop(stderr_w);

    let mut stdout = String::new();
    stdout_r.take(4096).read_to_string(&mut stdout).unwrap();

    let status = proc.wait().unwrap();
    proc.cleanup();

    let mut stderr = String::new();
    stderr_r.take(4096).read_to_string(&mut stderr).unwrap();

    assert!(
        status.success(),
        "cat should read file from @-path, stderr: {stderr}"
    );
    assert_eq!(stdout.trim(), "at-sign-ok");
}

/// Regression for bug #3: /tmp → /private/tmp canonicalization.
///
/// Writes to $TMPDIR inside the sandbox and reads it back. TMPDIR
/// is set to the canonicalized tmp_dir (/private/var/folders/...),
/// proving the symlink resolution works for write paths.
#[test]
fn seatbelt_write_to_tmpdir() {
    let (stdout_r, stdout_w) = pipe_pair();
    let (stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config("darwin-tmpdir");
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());

    let sb = new().unwrap();
    let mut proc = sb
        .launch(
            &cfg,
            "/bin/sh",
            &[
                "-c",
                "echo ok > $TMPDIR/write-test && cat $TMPDIR/write-test",
            ],
        )
        .unwrap();

    drop(stdout_w);
    drop(stderr_w);

    let mut stdout = String::new();
    stdout_r.take(4096).read_to_string(&mut stdout).unwrap();

    let mut stderr = String::new();
    stderr_r.take(4096).read_to_string(&mut stderr).unwrap();

    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(
        status.success(),
        "write to TMPDIR should succeed, stderr: {stderr}"
    );
    assert_eq!(stdout.trim(), "ok");
}

// ── Adversarial tests ──────────────────────────────────────────

/// Seatbelt denies reads outside allowed paths.
///
/// Creates a temp file, does NOT add its directory to read_paths,
/// and verifies /bin/cat cannot read it.
#[test]
fn seatbelt_denies_read_outside_paths() {
    let secret_dir = tempfile::tempdir().unwrap();
    let secret_canon = fs::canonicalize(secret_dir.path()).unwrap();
    let secret_file = secret_canon.join("secret.txt");
    fs::write(&secret_file, "should-not-read").unwrap();

    let (_stdout_r, stdout_w) = pipe_pair();
    let (_stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config("darwin-deny-read");
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());
    // Deliberately do NOT add secret_dir to read_paths.

    let sb = new().unwrap();
    let mut proc = sb
        .launch(&cfg, "/bin/cat", &[secret_file.to_str().unwrap()])
        .unwrap();

    drop(stdout_w);
    drop(stderr_w);

    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(
        !status.success(),
        "reading outside allowed paths should fail"
    );
}

/// Seatbelt denies directory listings outside explicitly allowed paths.
///
/// Non-root ancestors need metadata access for process startup and path
/// traversal, but must not expose directory contents when no volumes are
/// configured. The shell prints a marker and the command status so a launch
/// failure cannot be mistaken for a successful enforcement check. The root
/// directory is a documented Seatbelt bootstrap exception because dyld
/// requires data access.
#[test]
fn seatbelt_denies_unmounted_directory_listings() {
    for directory in [
        "/opt",
        "/etc",
        "/tmp",
        "/var",
        "/Users",
        "/private",
        "/private/var",
    ] {
        let (stdout_r, stdout_w) = pipe_pair();
        let (stderr_r, stderr_w) = pipe_pair();
        let mut cfg = base_config("darwin-deny-listing");
        cfg.stdout = Some(stdout_w.as_raw_fd());
        cfg.stderr = Some(stderr_w.as_raw_fd());

        let command = format!(
            "printf 'started\\n'; /bin/ls {directory}/ >/dev/null; printf 'ls-status=%s\\n' $?"
        );
        let sb = new().unwrap();
        let mut proc = sb.launch(&cfg, "/bin/sh", &["-c", &command]).unwrap();

        drop(stdout_w);
        drop(stderr_w);

        let mut stdout = String::new();
        stdout_r.take(4096).read_to_string(&mut stdout).unwrap();
        let mut stderr = String::new();
        stderr_r.take(4096).read_to_string(&mut stderr).unwrap();
        let status = proc.wait().unwrap();
        proc.cleanup();

        assert!(status.success(), "shell should execute for {directory}");
        assert!(
            stdout.contains("started\n"),
            "shell did not start: {stdout}"
        );
        assert!(
            stdout.contains("ls-status=1\n"),
            "ls should be denied for {directory}: {stdout}"
        );
        assert!(
            stderr.contains("Operation not permitted"),
            "ls should report Seatbelt denial for {directory}: {stderr}"
        );
    }
}

/// Metadata-only ancestor grants do not prevent listing an explicitly
/// configured nested path.
#[test]
fn seatbelt_allows_listing_inside_read_path() {
    let parent = tempfile::tempdir().unwrap();
    let nested = fs::canonicalize(parent.path()).unwrap().join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("allowed.txt"), "allowed\n").unwrap();

    let (stdout_r, stdout_w) = pipe_pair();
    let (_stderr_r, stderr_w) = pipe_pair();
    let mut cfg = base_config("darwin-allow-listing");
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());
    cfg.profile.read_paths = vec![nested.clone()];

    let sb = new().unwrap();
    let mut proc = sb
        .launch(&cfg, "/bin/ls", &["-1", nested.to_str().unwrap()])
        .unwrap();

    drop(stdout_w);
    drop(stderr_w);

    let mut stdout = String::new();
    stdout_r.take(4096).read_to_string(&mut stdout).unwrap();
    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(status.success(), "allowed directory should be listable");
    assert_eq!(stdout.trim(), "allowed.txt");
}

/// Seatbelt denies writes to read-only paths.
///
/// Adds a temp dir to read_paths but NOT write_paths, then
/// verifies a write attempt fails.
#[test]
fn seatbelt_denies_write_to_read_path() {
    let readonly_dir = tempfile::tempdir().unwrap();
    let readonly_canon = fs::canonicalize(readonly_dir.path()).unwrap();

    let (stdout_r, stdout_w) = pipe_pair();
    let (stderr_r, stderr_w) = pipe_pair();

    let target = readonly_canon.join("blocked.txt");

    let mut cfg = base_config("darwin-deny-write");
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());
    cfg.profile.read_paths = vec![readonly_canon];
    // Deliberately do NOT add to write_paths.

    let write_cmd = format!("echo x > {} 2>&1; echo exit=$?", target.to_str().unwrap());

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/sh", &["-c", &write_cmd]).unwrap();

    drop(stdout_w);
    drop(stderr_w);

    let mut stdout = String::new();
    stdout_r.take(4096).read_to_string(&mut stdout).unwrap();

    let mut stderr = String::new();
    stderr_r.take(4096).read_to_string(&mut stderr).unwrap();

    let _status = proc.wait().unwrap();
    proc.cleanup();

    assert!(
        !stdout.contains("exit=0") || stdout.contains("Operation not permitted"),
        "write to read-only path should fail, stdout: {stdout}, stderr: {stderr}"
    );
}

/// Seatbelt denies TCP network access.
///
/// The profile uses (deny default) and never grants network-outbound
/// for TCP. This is the macOS equivalent of the Linux seccomp
/// network-blocking test.
#[test]
fn seatbelt_denies_network() {
    let (stdout_r, stdout_w) = pipe_pair();
    let (_stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config("darwin-deny-net");
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());

    let sb = new().unwrap();
    let mut proc = sb
        .launch(
            &cfg,
            "/bin/sh",
            &[
                "-c",
                "/usr/bin/nc -w 1 1.1.1.1 80 </dev/null >/dev/null 2>&1 && echo CONNECTED || echo BLOCKED",
            ],
        )
        .unwrap();

    drop(stdout_w);
    drop(stderr_w);

    let mut stdout = String::new();
    stdout_r.take(4096).read_to_string(&mut stdout).unwrap();

    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(
        stdout.contains("BLOCKED") || !status.success(),
        "TCP connect should be blocked by Seatbelt, got: {stdout}"
    );
}

// ── Environment tests ──────────────────────────────────────────

/// Verify the sandbox provides a minimal environment.
///
/// env_clear() removes all parent env vars. minimal_env() adds
/// HOME, TMPDIR, PATH, LANG. Parent-specific vars like USER,
/// SHELL, TERM should be absent.
#[test]
fn seatbelt_env_minimal() {
    let (stdout_r, stdout_w) = pipe_pair();
    let (_stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config("darwin-env-min");
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/sh", &["-c", "env"]).unwrap();

    drop(stdout_w);
    drop(stderr_w);

    let mut stdout = String::new();
    stdout_r.take(8192).read_to_string(&mut stdout).unwrap();

    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(status.success(), "env should exit 0");

    let has = |key: &str| stdout.lines().any(|l| l.starts_with(&format!("{key}=")));

    assert!(has("HOME"), "HOME should be set");
    assert!(has("TMPDIR"), "TMPDIR should be set");
    assert!(has("PATH"), "PATH should be set");
    assert!(has("LANG"), "LANG should be set");

    assert!(!has("USER"), "USER should not leak through env_clear");
    assert!(!has("SHELL"), "SHELL should not leak through env_clear");
}

/// Verify dangerous env vars passed via cfg.env are stripped.
///
/// filter_caller_env strips DYLD_*, ARAPUCA_*, LD_*, and other
/// dangerous prefixes before they reach the child.
#[test]
fn seatbelt_env_dangerous_vars_stripped() {
    let (stdout_r, stdout_w) = pipe_pair();
    let (_stderr_r, stderr_w) = pipe_pair();

    let mut cfg = base_config("darwin-env-strip");
    cfg.stdout = Some(stdout_w.as_raw_fd());
    cfg.stderr = Some(stderr_w.as_raw_fd());
    cfg.env = vec![
        ("DYLD_INSERT_LIBRARIES".into(), "/evil.dylib".into()),
        ("ARAPUCA_SECRET".into(), "leak".into()),
        ("LD_PRELOAD".into(), "/evil.so".into()),
        ("SAFE_VAR".into(), "preserved".into()),
    ];

    let sb = new().unwrap();
    let mut proc = sb.launch(&cfg, "/bin/sh", &["-c", "env"]).unwrap();

    drop(stdout_w);
    drop(stderr_w);

    let mut stdout = String::new();
    stdout_r.take(8192).read_to_string(&mut stdout).unwrap();

    let status = proc.wait().unwrap();
    proc.cleanup();

    assert!(status.success(), "env should exit 0");

    let has = |key: &str| stdout.lines().any(|l| l.starts_with(&format!("{key}=")));

    assert!(!has("DYLD_INSERT_LIBRARIES"), "DYLD_* should be stripped");
    assert!(!has("ARAPUCA_SECRET"), "ARAPUCA_* should be stripped");
    assert!(!has("LD_PRELOAD"), "LD_* should be stripped");
    assert!(has("SAFE_VAR"), "safe vars should pass through");
}
