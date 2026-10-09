//! Arapuca CLI binary.
//!
//! Applies sandbox restrictions to the current process, then exec()s
//! the target command. This is a drop-in replacement for agent-sandbox.
//!
//! Configuration via environment variables:
//!
//!   ARAPUCA_READ_PATHS:   colon-separated readable paths
//!   ARAPUCA_WRITE_PATHS:  colon-separated writable paths
//!   ARAPUCA_RLIMIT_AS:    max virtual memory in bytes (opt-in only,
//!                         not set automatically — use for C programs
//!                         that must not allocate large virtual ranges)
//!   ARAPUCA_RLIMIT_NPROC: max processes (opt-in only, not set
//!                         automatically — per-UID system-wide limit)
//!   ARAPUCA_RLIMIT_CPU:   max CPU seconds (0 = no limit)
//!   ARAPUCA_RLIMIT_FSIZE: max file size in bytes (0 = no limit)
//!   ARAPUCA_RLIMIT_NOFILE: max open file descriptors (0 = no limit)
//!
//! Usage: arapuca -- command [args...]

use std::ffi::CString;
#[cfg(feature = "microvm")]
use std::io::IsTerminal;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.get(1).is_some_and(|a| a == "--wrapper-capabilities") {
        if args.len() != 2 || !cfg!(seccomp_supported) {
            std::process::exit(1);
        }
        print!("{}", arapuca::wrapper::UNIX_SOCKET_CAPABILITY);
        return;
    }

    // Dispatch subcommands before the sandbox path.
    if args.get(1).is_some_and(|a| a == "image") {
        image_subcommand(&args[2..]);
        return;
    }
    #[cfg(feature = "microvm")]
    if args.get(1).is_some_and(|a| a == "vm") {
        vm_subcommand(&args[2..]);
        return;
    }
    if args.get(1).is_some_and(|a| a == "run") {
        run_subcommand(&args[2..]);
        return;
    }

    // ── Dispatch guard ────────────────────────────────────────
    // Reject anything that is not a recognized subcommand or the
    // internal wrapper separator "--". Without this, unrecognized
    // args (flags, typos) fall through to the wrapper path which
    // runs with reduced sandbox enforcement.
    match args.get(1).map(|s| s.as_str()) {
        None => {
            print_usage();
            std::process::exit(1);
        }
        Some("-h" | "--help") => {
            print_usage();
            std::process::exit(0);
        }
        Some("-V" | "--version") => {
            eprintln!("arapuca {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        Some("--") => {} // wrapper path — fall through
        Some(arg) => {
            if arg.starts_with('-') {
                eprintln!("arapuca: unknown flag: {arg}");
            } else {
                eprintln!("arapuca: unknown subcommand: {arg}");
            }
            print_usage();
            std::process::exit(1);
        }
    }

    // ── Internal wrapper path ─────────────────────────────────
    // Only reachable when args[1] == "--". Used by the library
    // (Linux::launch, Darwin::launch) to apply Landlock, seccomp,
    // and rlimits to the target command via execve.

    // Audit FD: if set, write JSON status lines as each layer is applied.
    // The library creates a pipe and passes the write end via this env var.
    // Closed before execve so the target command cannot write to it.
    #[cfg(unix)]
    let audit_fd: Option<i32> = std::env::var("ARAPUCA_AUDIT_FD")
        .ok()
        .and_then(|s| s.parse().ok());

    // Find -- separator (scan from index 1 to prevent argv[0] manipulation).
    let sep_idx = args[1..].iter().position(|a| a == "--").map(|i| i + 1);
    debug_assert!(
        sep_idx == Some(1),
        "dispatch guard ensures args[1] == \"--\""
    );
    let cmd_idx = match sep_idx {
        Some(i) if i + 1 < args.len() => i + 1,
        _ => {
            print_usage();
            std::process::exit(1);
        }
    };

    let cmd = &args[cmd_idx];
    let cmd_args = &args[cmd_idx..];

    // Apply sandbox restrictions. Fail-closed: exit non-zero if any
    // step fails. The subprocess never runs unsandboxed.

    // 0. Sentinel check: the wrapper path must only be invoked by the
    // library, which sets ARAPUCA_WRAPPER=1. Without it, refuse to
    // run — prevents direct CLI invocations from bypassing the `run`
    // subcommand's sandbox configuration. Checked before command
    // resolution so invalid invocations fail early on all platforms.
    if std::env::var("ARAPUCA_WRAPPER").as_deref() != Ok("1") {
        eprintln!("arapuca: wrapper path requires library invocation (ARAPUCA_WRAPPER not set)");
        eprintln!("hint: use `arapuca run -- command` instead");
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    if let Err(e) = arapuca::wrapper::close_wrapper_exec_fd() {
        eprintln!("arapuca: {e}");
        std::process::exit(1);
    }
    let deny_unix_sockets = arapuca::wrapper::deny_unix_sockets_from_env().unwrap_or_else(|e| {
        eprintln!("arapuca: {e}");
        std::process::exit(1);
    });
    if let Err(e) = arapuca::wrapper::validate_unix_socket_policy(
        &arapuca::Profile {
            deny_unix_sockets,
            ..Default::default()
        },
        false,
    ) {
        #[cfg(unix)]
        audit_layer(audit_fd, "UnixSocketPolicy", false, Some(&e.to_string()));
        eprintln!("arapuca: {e}");
        std::process::exit(1);
    }

    // Resolve the command to an absolute path before applying sandbox
    // restrictions (Landlock would block the stat after apply). This
    // also fixes execve() which, unlike execvp(), does NOT search PATH.
    let cmd = if std::fs::metadata(cmd).is_ok() {
        // Already an absolute or relative path that exists — use it.
        // Canonicalize to handle relative paths.
        std::fs::canonicalize(cmd)
            .unwrap_or_else(|_| PathBuf::from(cmd))
            .to_string_lossy()
            .into_owned()
    } else {
        // Bare command name — resolve via PATH lookup.
        match which(cmd) {
            Some(path) => path.to_string_lossy().into_owned(),
            None => {
                eprintln!("arapuca: command not found: {cmd}");
                std::process::exit(1);
            }
        }
    };

    // 0a. Wait for cgroup readiness signal from parent.
    // The parent adds this process to the cgroup and then writes a
    // byte to the sync pipe. If the pipe closes without data (parent
    // failed to add PID), exit immediately.
    #[cfg(target_os = "linux")]
    if let Ok(fd_str) = std::env::var("ARAPUCA_CGROUP_SYNC_FD") {
        if let Ok(fd) = fd_str.parse::<i32>() {
            let mut buf = [0u8; 1];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), 1) };
            unsafe { libc::close(fd) };
            if n != 1 {
                std::process::exit(1);
            }
        }
    }

    // 0b. Unconditional setsid — detach from parent's session.
    // Called BEFORE pdeathsig since setsid clears it.
    // Tolerate EPERM (already a session leader from library's pre_exec).
    #[cfg(target_os = "linux")]
    let parent_pid = unsafe { libc::getppid() };
    #[cfg(unix)]
    {
        // SAFETY: setsid is async-signal-safe, no arguments.
        let ret = unsafe { libc::setsid() };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EPERM) {
                eprintln!("arapuca: setsid: {err}");
                std::process::exit(1);
            }
        }
    }

    // 0b2. Pdeathsig — immediately after setsid, before any other setup.
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
        if ret != 0 {
            eprintln!("arapuca: pdeathsig: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }
        if unsafe { libc::getppid() } != parent_pid {
            std::process::exit(1);
        }
        audit_layer(audit_fd, "Pdeathsig", true, None);
    }

    // 0c. Unconditional PR_SET_NO_NEW_PRIVS — prevent privilege
    // escalation via setuid binaries. Idempotent (no-op if already set
    // by landlock::restrict_self). Called unconditionally so this
    // invariant holds even when Landlock paths are empty.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is a simple setter.
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64) };
        if ret != 0 {
            eprintln!(
                "arapuca: PR_SET_NO_NEW_PRIVS: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(1);
        }
    }

    // 1. Landlock filesystem restrictions (Linux only).
    // 2. Seccomp BPF syscall filter (Linux only).
    #[cfg(target_os = "linux")]
    {
        let read_paths = env_paths("ARAPUCA_READ_PATHS");
        let write_paths = env_paths("ARAPUCA_WRITE_PATHS");
        let allow_exec = std::env::var("ARAPUCA_ALLOW_EXEC").as_deref() != Ok("0");

        let profile = arapuca::Profile {
            read_paths,
            write_paths,
            allow_exec,
            deny_unix_sockets,
            ..Default::default()
        };

        let seccomp_debug = std::env::var("ARAPUCA_SECCOMP_DEBUG").as_deref() == Ok("1");

        // Bind-mount resolv.conf when DNS capture is active (before
        // Landlock, since we need to write a temp file).
        if std::env::var("ARAPUCA_DNS_AUDIT_FD").is_ok() {
            let ok = arapuca::wrapper::override_resolv_conf();
            audit_layer(audit_fd, "ResolvConfOverride", ok, None);
        }

        // ── Unotify supervisor ─────────────────────────────────
        // Fork BEFORE Landlock, PID namespace, and seccomp.
        // The supervisor reads /proc/<pid>/mem which Landlock
        // excludes, and must be in the host PID namespace.
        #[cfg(seccomp_supported)]
        let unotify_config = arapuca::env::parse_unotify_config();
        #[cfg(seccomp_supported)]
        let unotify_fds = {
            if let Some(ref config) = unotify_config {
                if arapuca::unotify::unotify_available() {
                    let unotify_audit_fd = std::env::var("ARAPUCA_UNOTIFY_AUDIT_FD")
                        .ok()
                        .and_then(|s| s.parse::<i32>().ok())
                        .unwrap_or(-1);
                    if unotify_audit_fd >= 0 {
                        match arapuca::unotify::fork_unotify_supervisor(
                            config,
                            unotify_audit_fd,
                            seccomp_debug,
                        ) {
                            Ok(fds) => {
                                audit_layer(audit_fd, "UnotifySupervisor", true, None);
                                Some(fds)
                            }
                            Err(e) => {
                                audit_layer(
                                    audit_fd,
                                    "UnotifySupervisor",
                                    false,
                                    Some(&e.to_string()),
                                );
                                eprintln!("arapuca: unotify supervisor: {e}");
                                None
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    log::info!("unotify: not available on this kernel");
                    None
                }
            } else {
                None
            }
        };

        let target = std::path::Path::new(&cmd);
        if let Err(e) = arapuca::landlock::apply(&profile, Some(target)) {
            audit_layer(audit_fd, "Landlock", false, Some(&e.to_string()));
            eprintln!("arapuca: landlock: {e}");
            std::process::exit(1);
        }
        audit_layer(audit_fd, "Landlock", true, None);

        // A fresh network namespace starts with loopback down. Bring it up
        // before seccomp so the explicitly enabled listener capability is
        // usable without exposing the host network interfaces.
        if std::env::var("ARAPUCA_ALLOW_NETWORK_LISTENERS").as_deref() == Ok("1") {
            #[cfg(target_os = "linux")]
            if let Err(e) = arapuca::bridge::loopback_up() {
                audit_layer(audit_fd, "Loopback", false, Some(&e.to_string()));
                eprintln!("arapuca: loopback: {e}");
                std::process::exit(1);
            }
            #[cfg(target_os = "linux")]
            audit_layer(audit_fd, "Loopback", true, None);
        }

        // Bridge: fork a TCP-to-UDS relay before seccomp is applied.
        // Activated when ARAPUCA_PROXY_BRIDGE=<port>:<uds_path> is set.
        match arapuca::bridge::parse_bridge_env() {
            Ok(Some((port, uds_path))) => {
                let dns_audit_fd = std::env::var("ARAPUCA_DNS_AUDIT_FD")
                    .ok()
                    .and_then(|s| s.parse::<i32>().ok())
                    .filter(|&fd| fd >= 0);
                let bridge_port = match arapuca::bridge::fork_bridge(
                    port,
                    Some(&uds_path),
                    dns_audit_fd,
                    seccomp_debug,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        audit_layer(audit_fd, "ProxyBridge", false, Some(&e.to_string()));
                        eprintln!("arapuca: bridge: {e}");
                        std::process::exit(1);
                    }
                };
                let proxy = format!("http://127.0.0.1:{bridge_port}");
                unsafe {
                    std::env::set_var("HTTP_PROXY", &proxy);
                    std::env::set_var("HTTPS_PROXY", &proxy);
                    std::env::set_var("http_proxy", &proxy);
                    std::env::set_var("https_proxy", &proxy);
                }
                audit_layer(audit_fd, "ProxyBridge", true, None);
            }
            Ok(None) => {
                // DNS-only bridge: fork bridge for DNS capture without
                // TCP relay when ARAPUCA_DNS_AUDIT_FD is set.
                let dns_audit_fd = std::env::var("ARAPUCA_DNS_AUDIT_FD")
                    .ok()
                    .and_then(|s| s.parse::<i32>().ok())
                    .filter(|&fd| fd >= 0);
                if let Some(dns_fd) = dns_audit_fd {
                    match arapuca::bridge::fork_bridge(0, None, Some(dns_fd), seccomp_debug) {
                        Ok(_) => {
                            audit_layer(audit_fd, "DnsCapture", true, None);
                        }
                        Err(e) => {
                            audit_layer(audit_fd, "DnsCapture", false, Some(&e.to_string()));
                            eprintln!("arapuca: dns bridge: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("arapuca: bridge: {e}");
                std::process::exit(1);
            }
        }

        // PID namespace: unshare + fork between bridge and seccomp.
        // The parent (in host PID ns) stays as a signal relay; the
        // child (PID 1 in new ns) continues to seccomp + exec.
        #[cfg(seccomp_supported)]
        let mut pidns_host_pid: Option<i32> = None;
        if std::env::var("ARAPUCA_PID_NS").as_deref() == Ok("1") {
            let pid_report_fd: Option<i32> = std::env::var("ARAPUCA_PID_REPORT_FD")
                .ok()
                .and_then(|s| s.parse().ok());
            let dns_audit_fd: Option<i32> = std::env::var("ARAPUCA_DNS_AUDIT_FD")
                .ok()
                .and_then(|s| s.parse::<i32>().ok())
                .filter(|&fd| fd >= 0);
            let unotify_audit_fd: Option<i32> = std::env::var("ARAPUCA_UNOTIFY_AUDIT_FD")
                .ok()
                .and_then(|s| s.parse::<i32>().ok())
                .filter(|&fd| fd >= 0);

            if let Err(e) = arapuca::pidns::unshare_pidns() {
                audit_layer(audit_fd, "PidNamespace", false, Some(&e.to_string()));
                eprintln!("arapuca: pidns: {e}");
                std::process::exit(1);
            }
            audit_layer(audit_fd, "PidNamespace", true, None);

            // Parent never returns; child continues to seccomp.
            let (liveness_fd, _host_pid) = arapuca::pidns::fork_into_pidns(
                audit_fd,
                dns_audit_fd,
                unotify_audit_fd,
                pid_report_fd,
            );
            #[cfg(seccomp_supported)]
            {
                pidns_host_pid = Some(_host_pid);
            }

            // Child: re-set pdeathsig (fork clears it). The
            // getppid() race check is skipped inside the PID
            // namespace (getppid() returns 0 for cross-ns parent).
            let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
            if ret != 0 {
                eprintln!(
                    "arapuca: pidns child pdeathsig: {}",
                    std::io::Error::last_os_error()
                );
                unsafe { libc::_exit(1) };
            }
            if let Some(fd) = liveness_fd {
                arapuca::pidns::check_parent_liveness(fd);
            }
        }

        #[cfg(seccomp_supported)]
        {
            let seccomp_profile = match std::env::var("ARAPUCA_SECCOMP_PROFILE").as_deref() {
                Ok("baseline") => arapuca::SeccompProfile::Baseline,
                _ => arapuca::SeccompProfile::Strict,
            };
            if let Err(e) = arapuca::seccomp::apply(&seccomp_profile, deny_unix_sockets) {
                audit_layer(audit_fd, "Seccomp", false, Some(&e.to_string()));
                eprintln!("arapuca: seccomp: {e}");
                std::process::exit(1);
            }
            audit_layer(audit_fd, "Seccomp", true, None);
        }
        #[cfg(not(seccomp_supported))]
        {
            log::warn!("seccomp not available on this architecture — skipping");
            audit_layer(audit_fd, "Seccomp", true, None);
        }

        // ── Install USER_NOTIF filter LAST + send listener FD ─────
        // Must be after normal seccomp filters so USER_NOTIF is the
        // most recently installed filter (required for CONTINUE flag).
        #[cfg(seccomp_supported)]
        if let Some(ref fds) = unotify_fds {
            // Poll readiness first — confirms supervisor is alive.
            if arapuca::unotify::poll_readiness(fds.readiness_read, 5000).is_ok() {
                unsafe { libc::close(fds.readiness_read) };

                if let Some(ref config) = unotify_config {
                    let syscalls = arapuca::unotify::target_syscalls(
                        config.audit_file_access,
                        config.audit_network,
                    );
                    // The host PID is needed by the supervisor for
                    // pidfd_open(). In a PID namespace, getpid() returns
                    // the namespace-local PID (1), so we use the host PID
                    // piped from fork_into_pidns(). Outside a PID namespace,
                    // read_host_pid() reads /proc/self/stat — must happen
                    // BEFORE install_unotify_filter() because the filter
                    // intercepts openat and would deadlock.
                    let host_pid = pidns_host_pid.unwrap_or_else(arapuca::unotify::read_host_pid);
                    match arapuca::unotify::build_unotify_bpf(&syscalls)
                        .and_then(|bpf| arapuca::unotify::install_unotify_filter(&bpf))
                    {
                        Ok(listener_fd) => {
                            let mut msg = [0u8; 8];
                            msg[..4].copy_from_slice(&host_pid.to_ne_bytes());
                            msg[4..].copy_from_slice(&listener_fd.to_ne_bytes());
                            if !arapuca::unotify::write_all_raw(fds.socketpair_parent, &msg) {
                                eprintln!(
                                    "arapuca: send unotify fd: {}",
                                    std::io::Error::last_os_error()
                                );
                                unsafe { libc::_exit(1) };
                            }
                            // Keep listener_fd open — supervisor duplicates
                            // it via pidfd_getfd. CLOEXEC ensures it closes
                            // on exec.
                            unsafe {
                                libc::close(fds.socketpair_parent);
                            }
                        }
                        Err(e) => {
                            eprintln!("arapuca: unotify filter: {e}");
                            unsafe { libc::close(fds.socketpair_parent) };
                        }
                    }
                } else {
                    unsafe { libc::close(fds.socketpair_parent) };
                }
            } else {
                eprintln!("arapuca: unotify supervisor readiness timeout");
                unsafe {
                    libc::close(fds.readiness_read);
                    libc::close(fds.socketpair_parent);
                }
            }
        }
    }

    // 3. Resource limits from env vars (Unix only).
    #[cfg(unix)]
    if let Err(e) = arapuca::rlimit::apply_from_env() {
        audit_layer(audit_fd, "Rlimit", false, Some(&e.to_string()));
        eprintln!("arapuca: rlimit: {e}");
        std::process::exit(1);
    }
    #[cfg(unix)]
    audit_layer(audit_fd, "Rlimit", true, None);

    // Close audit FDs before exec — the target command must not inherit them.
    #[cfg(unix)]
    if let Some(fd) = audit_fd {
        // SAFETY: fd is a valid file descriptor from ARAPUCA_AUDIT_FD.
        unsafe { libc::close(fd) };
    }
    #[cfg(unix)]
    if let Some(fd) = std::env::var("ARAPUCA_DNS_AUDIT_FD")
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
    {
        unsafe { libc::close(fd) };
    }
    #[cfg(unix)]
    if let Some(fd) = std::env::var("ARAPUCA_UNOTIFY_AUDIT_FD")
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
    {
        unsafe { libc::close(fd) };
    }

    // Strip ARAPUCA_* env vars so the agent can't inspect its own
    // sandbox configuration. Non-ARAPUCA env vars (e.g., agent-facing
    // proxy socket config) are preserved.
    let env: Vec<(CString, CString)> = std::env::vars()
        .filter(|(k, _)| !k.starts_with("ARAPUCA_"))
        .filter_map(|(k, v)| {
            let k = CString::new(k).ok()?;
            let v = CString::new(v).ok()?;
            Some((k, v))
        })
        .collect();

    // Build the exec arguments.
    let c_cmd = CString::new(cmd.as_str()).unwrap_or_else(|_| {
        eprintln!("arapuca: invalid command: {cmd}");
        std::process::exit(1);
    });

    let c_args: Vec<CString> = cmd_args
        .iter()
        .map(|a| {
            CString::new(a.as_str()).unwrap_or_else(|_| {
                eprintln!("arapuca: invalid argument (contains null byte): {a}");
                std::process::exit(1);
            })
        })
        .collect();

    // Exec the target command (Unix: replaces process, Windows: spawn-and-wait).
    #[cfg(unix)]
    {
        // SAFETY: All CStrings are valid, null-terminated, and live until
        // execve replaces the process image.
        unsafe {
            let argv: Vec<*const libc::c_char> = c_args
                .iter()
                .map(|a| a.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();

            let envp: Vec<*const libc::c_char> = env
                .iter()
                .map(|(k, v)| {
                    // Leak a "key=value" CString for the envp array.
                    // This is fine because execve replaces the process.
                    let kv = format!("{}={}", k.to_string_lossy(), v.to_string_lossy());
                    CString::new(kv)
                        .unwrap_or_else(|_| {
                            eprintln!(
                                "arapuca: invalid env var (contains null byte): key={}",
                                k.to_string_lossy()
                            );
                            std::process::exit(1);
                        })
                        .into_raw() as *const libc::c_char
                })
                .chain(std::iter::once(std::ptr::null()))
                .collect();

            let ret = libc::execve(c_cmd.as_ptr(), argv.as_ptr(), envp.as_ptr());
            if ret == -1 {
                eprintln!("arapuca: exec {}: {}", cmd, std::io::Error::last_os_error());
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (c_cmd, c_args, env);
        eprintln!("arapuca: binary not yet supported on this platform");
        std::process::exit(1);
    }
}

// ─── Run subcommand ───────────────────────────────────────────

fn run_subcommand(args: &[String]) {
    use arapuca::platform::Sandbox;

    let mut read_only_paths: Vec<PathBuf> = Vec::new();
    let mut read_write_paths: Vec<PathBuf> = Vec::new();
    let mut user_env: Vec<(String, String)> = Vec::new();
    let mut timeout: Option<u64> = None;
    let mut memory: Option<u64> = None;
    let mut cpus: Option<u32> = None;
    let mut pids: Option<u32> = None;
    let mut task_id: Option<String> = None;
    let mut cwd: Option<PathBuf> = None;
    let mut seccomp_profile = arapuca::SeccompProfile::Strict;
    let mut deny_unix_sockets = false;
    #[cfg(unix)]
    let mut tty = false;
    #[cfg(target_os = "linux")]
    let mut allowed_hosts: Vec<arapuca::bridge::AllowedHost> = Vec::new();
    let mut deny_network = false;
    let mut no_pid_ns = false;
    let mut audit_files = false;
    #[allow(unused_mut, unused_variables)]
    let mut seccomp_debug = false;
    let mut audit_network = false;
    let mut allow_proxy_env = false;
    let mut allow_keychain = false;
    let mut allow_network_listeners = false;
    let mut lpac = false;

    // Find -- separator.
    let sep_pos = args.iter().position(|a| a == "--");
    let flag_args = match sep_pos {
        Some(pos) => &args[..pos],
        None => args,
    };
    let cmd_args: &[String] = match sep_pos {
        Some(pos) if pos + 1 < args.len() => &args[pos + 1..],
        _ => {
            eprintln!("usage: arapuca run [flags] -- command [args...]");
            eprintln!();
            eprintln!("flags:");
            eprintln!("  -v /path[:ro]      allow path access (rw default, :ro read-only)");
            eprintln!("  --cwd /path        set working directory (must be within a mount)");
            eprintln!("  --env KEY=VALUE    pass environment variable");
            eprintln!("  --timeout N        kill after N seconds");
            eprintln!("  --memory N         memory limit in MB");
            eprintln!("  --cpus N           CPU limit (percentage, 200 = 2 cores)");
            eprintln!("  --pids N           max number of PIDs");
            eprintln!("  --task-id NAME     identifier for cgroup and audit");
            eprintln!("  --allow-host H:P   allow HTTPS to host:port or *.domain:port");
            eprintln!(
                "  --deny-network     block all network; capture DNS queries as audit events"
            );
            eprintln!("  --audit-files      emit file access and process spawn audit events");
            eprintln!("  --seccomp-debug    log blocked syscalls to stderr instead of killing");
            eprintln!("  --audit-network    emit network connection audit events");
            eprintln!(
                "  --allow-proxy-env  forward HTTP(S)_PROXY/ALL_PROXY/NO_PROXY from the caller's env"
            );
            eprintln!("                     (proxy routing only; TLS trust-anchor vars such as");
            eprintln!("                     SSL_CERT_FILE/CURL_CA_BUNDLE are not forwarded)");
            eprintln!("  --seccomp MODE     seccomp profile: strict (default) or baseline");
            eprintln!("  --no-unix-sockets  deny Unix sockets (Linux x86_64/aarch64 only)");
            eprintln!("  --no-pid-ns        disable PID namespace isolation");
            eprintln!("  --lpac             run as a Less Privileged AppContainer (Windows only);");
            eprintln!(
                "                     may break binaries that need registry/DLL access outside"
            );
            eprintln!("                     the LPAC allowlist");
            eprintln!(
                "  --allow-keychain   allow macOS Keychain access; sets HOME to your \
                 home dir (macOS only)"
            );
            eprintln!(
                "  --allow-network-listeners  allow TCP bind/inbound (macOS Seatbelt cannot \
                 strictly confine listeners to loopback)"
            );
            eprintln!("  -t, --tty          allocate a PTY for interactive programs");
            if sep_pos.is_none() && !args.is_empty() {
                eprintln!();
                eprintln!("hint: did you forget '--' before the command?");
            }
            std::process::exit(125);
        }
    };

    // Parse flags.
    let mut i = 0;
    while i < flag_args.len() {
        match flag_args[i].as_str() {
            "-v" | "--volume" => {
                i += 1;
                let spec = flag_args.get(i).unwrap_or_else(|| {
                    eprintln!("-v requires a path");
                    std::process::exit(125);
                });
                let (path, ro) = parse_volume_spec(spec);
                if path.as_os_str().is_empty() {
                    eprintln!("arapuca run: -v path must not be empty");
                    std::process::exit(125);
                }
                if !path.is_absolute() {
                    eprintln!("arapuca run: -v path must be absolute: {}", path.display());
                    std::process::exit(125);
                }
                if ro {
                    read_only_paths.push(path);
                } else {
                    read_write_paths.push(path);
                }
            }
            "--env" => {
                i += 1;
                let kv = flag_args.get(i).unwrap_or_else(|| {
                    eprintln!("--env requires KEY=VALUE");
                    std::process::exit(125);
                });
                if let Some((k, v)) = kv.split_once('=') {
                    if k.is_empty() {
                        eprintln!("arapuca run: --env key must not be empty");
                        std::process::exit(125);
                    }
                    // Sandbox-managed keys cannot be overridden.
                    if matches!(k, "HOME" | "TMPDIR" | "PATH" | "LANG") {
                        eprintln!("arapuca run: --env cannot override sandbox-managed var: {k}");
                        std::process::exit(125);
                    }
                    // Reject vars that the library's filter_caller_env
                    // would silently drop — fail loud at the CLI boundary.
                    let probe = vec![(k.to_string(), v.to_string())];
                    if arapuca::env::filter_caller_env(&probe).passed.is_empty() {
                        eprintln!("arapuca run: --env {k} is blocked (sandbox security)");
                        std::process::exit(125);
                    }
                    user_env.push((k.to_string(), v.to_string()));
                } else {
                    eprintln!("arapuca run: invalid --env: {kv} (expected KEY=VALUE)");
                    std::process::exit(125);
                }
            }
            "--timeout" => {
                i += 1;
                let secs: u64 = flag_args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("--timeout requires a positive integer (seconds)");
                        std::process::exit(125);
                    });
                if secs == 0 {
                    eprintln!("--timeout must be > 0");
                    std::process::exit(125);
                }
                timeout = Some(secs);
            }
            "--memory" => {
                i += 1;
                memory = Some(
                    flag_args
                        .get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or_else(|| {
                            eprintln!("--memory requires a positive integer (MB)");
                            std::process::exit(125);
                        }),
                );
                if memory == Some(0) {
                    eprintln!("--memory must be > 0");
                    std::process::exit(125);
                }
            }
            "--cpus" => {
                i += 1;
                cpus = Some(
                    flag_args
                        .get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or_else(|| {
                            eprintln!("--cpus requires a positive integer");
                            std::process::exit(125);
                        }),
                );
                if cpus == Some(0) {
                    eprintln!("--cpus must be > 0");
                    std::process::exit(125);
                }
            }
            "--pids" => {
                i += 1;
                pids = Some(
                    flag_args
                        .get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or_else(|| {
                            eprintln!("--pids requires a positive integer");
                            std::process::exit(125);
                        }),
                );
                if pids == Some(0) {
                    eprintln!("--pids must be > 0");
                    std::process::exit(125);
                }
            }
            "--task-id" => {
                i += 1;
                task_id = Some(
                    flag_args
                        .get(i)
                        .unwrap_or_else(|| {
                            eprintln!("--task-id requires a value");
                            std::process::exit(125);
                        })
                        .clone(),
                );
            }
            "--allow-host" => {
                i += 1;
                let spec = flag_args.get(i).unwrap_or_else(|| {
                    eprintln!("--allow-host requires host:port");
                    std::process::exit(125);
                });
                #[cfg(target_os = "linux")]
                {
                    let (host, port) = parse_allow_host(spec);
                    allowed_hosts.push(arapuca::bridge::AllowedHost::new(host, port));
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = spec;
                    eprintln!("arapuca run: --allow-host requires Linux (network namespaces)");
                    std::process::exit(125);
                }
            }
            "--deny-network" => {
                deny_network = true;
                #[cfg(not(target_os = "linux"))]
                eprintln!(
                    "arapuca run: --deny-network: DNS capture is Linux-only; \
                     network denial on this platform is handled by the native sandbox"
                );
            }
            #[cfg(unix)]
            "-t" | "--tty" => {
                tty = true;
            }
            "--seccomp" => {
                i += 1;
                let mode = flag_args.get(i).unwrap_or_else(|| {
                    eprintln!("--seccomp requires a mode (strict or baseline)");
                    std::process::exit(125);
                });
                seccomp_profile = match mode.as_str() {
                    "strict" => arapuca::SeccompProfile::Strict,
                    "baseline" => arapuca::SeccompProfile::Baseline,
                    other => {
                        eprintln!("arapuca run: unknown seccomp profile: {other}");
                        eprintln!("valid profiles: strict, baseline");
                        std::process::exit(125);
                    }
                };
            }
            "--no-pid-ns" => {
                no_pid_ns = true;
            }
            "--no-unix-sockets" => {
                deny_unix_sockets = true;
            }
            "--lpac" => {
                lpac = true;
                #[cfg(not(windows))]
                eprintln!("arapuca run: --lpac is Windows-only; ignored on this platform");
            }
            "--audit-files" => {
                audit_files = true;
            }
            "--allow-proxy-env" => {
                allow_proxy_env = true;
                #[cfg(not(target_os = "macos"))]
                eprintln!(
                    "arapuca run: --allow-proxy-env is macOS-only; \
                     ignored on this platform"
                );
            }
            "--allow-keychain" => {
                allow_keychain = true;
                #[cfg(not(target_os = "macos"))]
                eprintln!(
                    "arapuca run: --allow-keychain has no effect on this platform \
                     (macOS Keychain only)"
                );
            }
            "--allow-network-listeners" => {
                allow_network_listeners = true;
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                eprintln!("arapuca run: --allow-network-listeners has no effect on this platform");
            }
            "--audit-network" => {
                audit_network = true;
            }
            "--seccomp-debug" => {
                seccomp_debug = true;
            }
            "--cwd" => {
                i += 1;
                let path = flag_args.get(i).unwrap_or_else(|| {
                    eprintln!("--cwd requires a path");
                    std::process::exit(125);
                });
                let p = PathBuf::from(path);
                if !p.is_absolute() {
                    eprintln!("arapuca run: --cwd path must be absolute: {}", p.display());
                    std::process::exit(125);
                }
                cwd = Some(p);
            }
            other => {
                eprintln!("arapuca run: unknown flag: {other}");
                eprintln!("hint: did you forget '--' before the command?");
                std::process::exit(125);
            }
        }
        i += 1;
    }

    // ── Flag validation ────────────────────────────────────────
    if let Err(e) = (arapuca::Profile {
        deny_unix_sockets,
        ..Default::default()
    })
    .validate_unix_socket_policy()
    {
        eprintln!("arapuca run: {e}");
        std::process::exit(125);
    }
    if deny_network && allow_network_listeners {
        eprintln!(
            "arapuca run: --deny-network and --allow-network-listeners are mutually exclusive"
        );
        std::process::exit(125);
    }
    #[cfg(target_os = "linux")]
    if deny_network && !allowed_hosts.is_empty() {
        eprintln!("arapuca run: --deny-network and --allow-host are mutually exclusive");
        std::process::exit(125);
    }

    // ── CONNECT proxy for --allow-host ────────────────────────
    #[cfg(target_os = "linux")]
    let (connect_proxy_socket, connect_proxy_pid, connect_proxy_pidfd) =
        if !allowed_hosts.is_empty() {
            let (path, pid, pidfd) = fork_connect_proxy(&allowed_hosts, seccomp_debug);
            (Some(path), Some(pid), Some(pidfd))
        } else {
            (None, None, None)
        };
    #[cfg(not(target_os = "linux"))]
    let connect_proxy_socket: Option<PathBuf> = None;

    // Merge default paths with user-specified paths.
    let (mut default_read, mut default_write) = arapuca::env::default_sandbox_paths();

    // Baseline seccomp: add /proc and specific /sys subtrees for
    // runtimes that need them (Bun/JSC reads /proc/self/maps,
    // /proc/self/cgroup, /proc/version, /sys/devices/system/cpu/online
    // during allocator init). Using /sys/devices/system/cpu instead
    // of /sys avoids conflicting with reject_cgroup_paths (which
    // rejects ancestors of /sys/fs/cgroup).
    if seccomp_profile == arapuca::SeccompProfile::Baseline {
        default_read.push(PathBuf::from("/proc"));
        default_read.push(PathBuf::from("/sys/devices/system/cpu"));
    }

    default_read.extend(read_only_paths);
    default_write.extend(read_write_paths);

    let read_paths = arapuca::env::canonicalize_paths(&default_read);
    let write_paths = arapuca::env::canonicalize_paths(&default_write);

    #[cfg(unix)]
    {
        arapuca::reject_cgroup_paths(&read_paths).unwrap_or_else(|e| {
            eprintln!("arapuca run: {e}");
            std::process::exit(125);
        });
        arapuca::reject_cgroup_paths(&write_paths).unwrap_or_else(|e| {
            eprintln!("arapuca run: {e}");
            std::process::exit(125);
        });
    }

    if let Some(ref cwd_path) = cwd {
        let canonical = cwd_path.canonicalize().unwrap_or_else(|e| {
            eprintln!("arapuca run: --cwd path cannot be resolved: {e}");
            std::process::exit(125);
        });
        if !canonical.is_dir() {
            eprintln!(
                "arapuca run: --cwd path is not a directory: {}",
                canonical.display()
            );
            std::process::exit(125);
        }
        let in_mounts = read_paths
            .iter()
            .chain(write_paths.iter())
            .any(|p| canonical.starts_with(p));
        if !in_mounts {
            eprintln!("arapuca run: --cwd path must be within a mounted path");
            std::process::exit(125);
        }
        cwd = Some(canonical);
    }

    let task = task_id.unwrap_or_else(|| format!("run-{}", std::process::id()));
    arapuca::sanitize_task_id(&task).unwrap_or_else(|e| {
        eprintln!("arapuca run: {e}");
        std::process::exit(125);
    });

    let use_netns = connect_proxy_socket.is_some() || deny_network || allow_network_listeners;
    let profile = arapuca::Profile {
        read_paths,
        write_paths,
        max_memory_mb: memory.unwrap_or(0),
        max_cpu_pct: cpus.unwrap_or(0),
        max_pids: pids.unwrap_or(0),
        allow_exec: true,
        use_netns,
        use_pidns: use_netns && !no_pid_ns,
        dns_capture: deny_network,
        lpac,
        seccomp_profile,
        deny_unix_sockets,
        audit_file_access: audit_files,
        audit_network: audit_network || deny_network,
        seccomp_debug,
        allow_proxy_env,
        allow_keychain,
        allow_network_listeners,
        ..Default::default()
    };

    // ── TTY mode validation ────────────────────────────────────
    #[cfg(unix)]
    if tty {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            eprintln!("arapuca run: -t requires stdin and stdout to be a terminal");
            std::process::exit(125);
        }
        // Inject TERM unless the user already specified it.
        if !user_env.iter().any(|(k, _)| k == "TERM") {
            if let Ok(term) = std::env::var("TERM") {
                let sanitized: String = term
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c))
                    .take(64)
                    .collect();
                if !sanitized.is_empty() {
                    user_env.push(("TERM".into(), sanitized));
                }
            }
        }
    }

    let config = arapuca::Config {
        profile,
        socket_dir: PathBuf::new(),
        task_id: task,
        phase: "run".into(),
        work_dir: cwd,
        #[cfg(unix)]
        stdin: None,
        #[cfg(unix)]
        stdout: None,
        #[cfg(unix)]
        stderr: None,
        #[cfg(unix)]
        extra_fds: Vec::new(),
        #[cfg(unix)]
        tty,
        network_proxy_socket: connect_proxy_socket.clone(),
        #[cfg(target_os = "linux")]
        allowed_hosts: Vec::new(),
        env: user_env,
        audit_sink: None,
        audit_verbosity: arapuca::audit::AuditVerbosity::Standard,
        audit_principal: None,
        audit_correlation_id: None,
    };

    let sandbox = arapuca::platform::new().unwrap_or_else(|e| {
        eprintln!("arapuca run: sandbox init: {e}");
        std::process::exit(125);
    });

    let cmd = &cmd_args[0];
    let cmd_rest: Vec<&str> = cmd_args[1..].iter().map(|s| s.as_str()).collect();

    let mut process = match sandbox.launch(&config, cmd, &cmd_rest) {
        Ok(p) => p,
        Err(e) => {
            #[cfg(target_os = "linux")]
            cleanup_connect_proxy(
                connect_proxy_pid,
                connect_proxy_pidfd,
                &connect_proxy_socket,
            );
            eprintln!("arapuca run: launch failed: {e}");
            std::process::exit(125);
        }
    };

    // ── TTY mode: I/O proxy loop with unified signal handler ───
    #[cfg(unix)]
    if tty {
        let exit_code = run_pty_loop(&mut process, timeout);

        process.cleanup();

        #[cfg(target_os = "linux")]
        cleanup_connect_proxy(
            connect_proxy_pid,
            connect_proxy_pidfd,
            &connect_proxy_socket,
        );

        std::process::exit(exit_code);
    }

    // ── Non-TTY mode: plain wait ─────────────────────────────
    // Forward SIGINT/SIGTERM to the sandboxed child.
    #[cfg(unix)]
    install_signal_forwarder(process.pid() as i32);

    // Timeout enforcement (Unix only — signals are not portable).
    #[cfg(not(unix))]
    let _ = timeout;

    #[cfg(unix)]
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    #[cfg(unix)]
    if let Some(secs) = timeout {
        let done_clone = std::sync::Arc::clone(&done);
        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            std::thread::sleep(std::time::Duration::from_secs(secs));
            if done_clone.load(Ordering::Acquire) {
                return;
            }
            eprintln!("arapuca run: timeout ({secs}s), sending SIGTERM");
            signal_child(libc::SIGTERM);
            std::thread::sleep(std::time::Duration::from_secs(5));
            if done_clone.load(Ordering::Acquire) {
                return;
            }
            signal_child(libc::SIGKILL);
        });
    }

    let status = process.wait();

    #[cfg(unix)]
    done.store(true, std::sync::atomic::Ordering::Release);

    #[cfg(unix)]
    {
        CHILD_PID.store(0, std::sync::atomic::Ordering::Release);
        let pidfd = CHILD_PIDFD.swap(-1, std::sync::atomic::Ordering::AcqRel);
        if pidfd >= 0 {
            // SAFETY: pidfd is a valid open file descriptor.
            unsafe { libc::close(pidfd) };
        }
    }

    let exit_code = match status {
        #[allow(clippy::manual_unwrap_or)]
        Ok(s) => {
            if let Some(code) = s.code() {
                code
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    128 + s.signal().unwrap_or(9)
                }
                #[cfg(not(unix))]
                {
                    137
                }
            }
        }
        Err(e) => {
            eprintln!("arapuca run: wait: {e}");
            125
        }
    };

    process.cleanup();

    #[cfg(target_os = "linux")]
    cleanup_connect_proxy(
        connect_proxy_pid,
        connect_proxy_pidfd,
        &connect_proxy_socket,
    );

    std::process::exit(exit_code);
}

#[cfg(target_os = "linux")]
fn cleanup_connect_proxy(pid: Option<i32>, pidfd: Option<i32>, socket: &Option<PathBuf>) {
    // Send SIGKILL via pidfd (race-free) or fall back to kill().
    // Without this fallback, waitpid blocks forever if pidfd_open
    // failed (kernel < 5.3, EMFILE, etc.).
    let sent_via_pidfd = if let Some(fd) = pidfd {
        if fd >= 0 {
            // SAFETY: pidfd_send_signal with valid pidfd.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd,
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                );
            }
            true
        } else {
            false
        }
    } else {
        false
    };
    if !sent_via_pidfd {
        if let Some(pid) = pid {
            // SAFETY: kill with valid pid.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
    if let Some(pid) = pid {
        // SAFETY: waitpid with valid pid. Retry on EINTR.
        loop {
            let ret = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
            if ret != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
    }
    if let Some(fd) = pidfd {
        if fd >= 0 {
            // SAFETY: close valid pidfd.
            unsafe { libc::close(fd) };
        }
    }
    if let Some(sock) = socket {
        if let Some(parent) = sock.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

// ─── PTY I/O proxy loop ───────────────────────────────────────
//
// Handles the entire post-spawn lifecycle in TTY mode: signal
// handler install, timeout thread, raw mode, poll(2) I/O
// proxying, SIGWINCH forwarding, child reap, and exit code
// extraction.

#[cfg(unix)]
static TTY_SIGNAL_RECEIVED: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

#[cfg(unix)]
static TTY_SIGNAL_COUNT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

#[cfg(unix)]
fn run_pty_loop(process: &mut arapuca::Process, timeout: Option<u64>) -> i32 {
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::Ordering;

    let master_fd = match process.pty_master() {
        Some(fd) => fd.as_raw_fd(),
        None => {
            eprintln!("arapuca run: -t was set but no PTY master available");
            return 125;
        }
    };

    let stdin_fd: i32 = 0;
    let stdout_fd: i32 = 1;

    // ── Store child PID for signal forwarding ──────────────────
    store_child_pid(process.pid() as i32);
    TTY_SIGNAL_COUNT.store(0, Ordering::Release);
    TTY_SIGNAL_RECEIVED.store(0, Ordering::Release);

    // ── Set O_NONBLOCK on stdin and PTY master ────────────────
    // SAFETY: F_GETFL/F_SETFL on valid FDs.
    let saved_stdin_flags = unsafe { libc::fcntl(stdin_fd, libc::F_GETFL) };
    unsafe {
        libc::fcntl(
            stdin_fd,
            libc::F_SETFL,
            saved_stdin_flags | libc::O_NONBLOCK,
        )
    };
    let master_flags = unsafe { libc::fcntl(master_fd, libc::F_GETFL) };
    unsafe { libc::fcntl(master_fd, libc::F_SETFL, master_flags | libc::O_NONBLOCK) };

    // ── Timeout thread ────────────────────────────────────────
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if let Some(secs) = timeout {
        let done_clone = std::sync::Arc::clone(&done);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            if done_clone.load(Ordering::Acquire) {
                return;
            }
            eprintln!("arapuca run: timeout ({secs}s), sending SIGTERM");
            signal_child(libc::SIGTERM);
            std::thread::sleep(std::time::Duration::from_secs(5));
            if done_clone.load(Ordering::Acquire) {
                return;
            }
            signal_child(libc::SIGKILL);
        });
    }

    // ── Install signal handlers + enter raw mode ───────────────
    // Install handlers BEFORE entering raw mode so that a signal
    // in the window between tcsetattr(raw) and handler install
    // doesn't leave the terminal stuck in raw mode. restore_termios()
    // is a no-op when CLEANUP_FD == -1 (before enter()), so this
    // is safe.
    install_tty_signal_handler();
    arapuca::terminal::install_sigwinch_handler();

    let _raw_guard = arapuca::terminal::RawModeGuard::enter(stdin_fd).unwrap_or_else(|e| {
        if saved_stdin_flags >= 0 {
            unsafe { libc::fcntl(stdin_fd, libc::F_SETFL, saved_stdin_flags) };
        }
        eprintln!("arapuca run: raw mode: {e}");
        std::process::exit(125);
    });

    // ── poll(2) I/O loop ──────────────────────────────────────
    //
    // Stdin data is buffered in pending_write and drained to the PTY
    // master via POLLOUT, preventing a deadlock when both directions
    // are under pressure (child producing output while input buffer
    // is full). Stdout writes remain synchronous — stdout is always
    // a terminal (enforced by -t validation) which consumes quickly.

    const PTY_WRITE_BUF_HIGH: usize = 256 * 1024;
    const PTY_WRITE_BUF_LOW: usize = 128 * 1024;

    let mut pending_write: std::collections::VecDeque<u8> =
        std::collections::VecDeque::with_capacity(PTY_WRITE_BUF_HIGH);

    let mut fds = [
        libc::pollfd {
            fd: master_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stdin_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let mut buf = [0u8; 65536];

    loop {
        // Set events dynamically each iteration.
        // Master: POLLIN always; POLLOUT only when buffer has data.
        fds[0].events = libc::POLLIN
            | if pending_write.is_empty() {
                0
            } else {
                libc::POLLOUT
            };
        // Stdin: POLLIN only when buffer is below low water mark
        // (hysteresis prevents oscillation). Reserve fd=-1 for
        // permanent EOF — use events for back-pressure.
        if fds[1].fd >= 0 {
            fds[1].events = if pending_write.len() < PTY_WRITE_BUF_LOW {
                libc::POLLIN
            } else {
                0
            };
        }

        // SIGWINCH: forward terminal resize to PTY master.
        if arapuca::terminal::SIGWINCH_RECEIVED.swap(false, Ordering::AcqRel) {
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            // SAFETY: TIOCGWINSZ on stdin, TIOCSWINSZ on master.
            if unsafe { libc::ioctl(stdin_fd, libc::TIOCGWINSZ, &mut ws) } == 0 {
                unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws) };
            }
        }

        // SAFETY: poll with valid pollfd array, 100ms timeout.
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, 100) };
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }

        // ── Handler ordering: POLLIN → POLLHUP → POLLOUT → stdin ──

        // 1. PTY master → stdout (drain child output first).
        if fds[0].revents & libc::POLLIN != 0 {
            // SAFETY: master_fd is valid, buf is stack-local.
            let n = unsafe {
                libc::read(
                    master_fd,
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n > 0 {
                write_all_fd(stdout_fd, &buf[..n as usize]);
            }
        }

        // 2. POLLHUP from master: drain remaining data, discard
        //    pending writes (slave is closed — writes return EIO),
        //    then break.
        if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            loop {
                let n = unsafe {
                    libc::read(
                        master_fd,
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len(),
                    )
                };
                if n > 0 {
                    write_all_fd(stdout_fd, &buf[..n as usize]);
                } else {
                    break;
                }
            }
            pending_write.clear();
            break;
        }

        // 3. Drain pending_write to PTY master (skip if POLLHUP).
        if fds[0].revents & libc::POLLOUT != 0 && !pending_write.is_empty() {
            let contig = pending_write.make_contiguous();
            // SAFETY: master_fd is valid and O_NONBLOCK; contig is
            // a valid contiguous buffer from VecDeque.
            let n = unsafe {
                libc::write(
                    master_fd,
                    contig.as_ptr().cast::<libc::c_void>(),
                    contig.len(),
                )
            };
            if n > 0 {
                pending_write.drain(..n as usize);
            } else if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINTR)
                    && err.raw_os_error() != Some(libc::EAGAIN)
                {
                    break;
                }
            }
            // n == 0: treat as EAGAIN, retry next iteration.
        }

        // 4. stdin → pending_write buffer.
        if fds[1].revents & libc::POLLIN != 0 {
            // SAFETY: stdin_fd is valid, buf is stack-local.
            let n =
                unsafe { libc::read(stdin_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n > 0 {
                pending_write.extend(&buf[..n as usize]);
            } else if n == 0 {
                fds[1].fd = -1;
            }
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            fds[1].fd = -1;
        }
    }

    // ── Restore stdin flags ───────────────────────────────────
    if saved_stdin_flags >= 0 {
        // SAFETY: restoring saved flags.
        unsafe { libc::fcntl(stdin_fd, libc::F_SETFL, saved_stdin_flags) };
    }
    // RawModeGuard::drop restores terminal state.
    drop(_raw_guard);

    // ── Reap child and collect exit code ──────────────────────
    let exit_code = match process.wait() {
        #[allow(clippy::manual_unwrap_or)]
        Ok(s) => {
            if let Some(code) = s.code() {
                code
            } else {
                use std::os::unix::process::ExitStatusExt;
                128 + s.signal().unwrap_or(9)
            }
        }
        Err(e) => {
            eprintln!("arapuca run: wait: {e}");
            125
        }
    };

    // Disable timeout thread AFTER wait (not before — otherwise a
    // child that closes its PTY but keeps running hangs forever).
    done.store(true, Ordering::Release);

    // Clear child PID AFTER setting done (prevents kill(0, sig) race).
    CHILD_PID.store(0, Ordering::Release);
    let pidfd = CHILD_PIDFD.swap(-1, Ordering::AcqRel);
    if pidfd >= 0 {
        // SAFETY: pidfd is a valid open file descriptor.
        unsafe { libc::close(pidfd) };
    }

    // Check if we exited due to a signal (for correct exit code).
    let sig = TTY_SIGNAL_RECEIVED.load(Ordering::Acquire);
    if sig > 0 && exit_code == 0 {
        128 + sig
    } else {
        exit_code
    }
}

/// Write all bytes to a raw FD, retrying on EINTR and EAGAIN.
#[cfg(unix)]
fn write_all_fd(fd: i32, data: &[u8]) {
    let mut offset = 0;
    while offset < data.len() {
        // SAFETY: fd is valid, data[offset..] is a valid buffer.
        let n = unsafe {
            libc::write(
                fd,
                data[offset..].as_ptr().cast::<libc::c_void>(),
                data.len() - offset,
            )
        };
        if n > 0 {
            offset += n as usize;
        } else if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => {
                    // SAFETY: poll on a single FD waiting for writability.
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    unsafe { libc::poll(&mut pfd, 1, 100) };
                    continue;
                }
                _ => break,
            }
        } else {
            break;
        }
    }
}

/// Install the unified TTY signal handler that restores the terminal
/// and forwards the signal to the child with escalation.
#[cfg(unix)]
fn install_tty_signal_handler() {
    use std::sync::atomic::Ordering;

    extern "C" fn tty_handler(sig: libc::c_int) {
        // 1. Restore terminal state (async-signal-safe).
        arapuca::terminal::restore_termios();

        // 2. Forward to child with escalation.
        let count = TTY_SIGNAL_COUNT.fetch_add(1, Ordering::AcqRel);
        let child_sig = if count == 0 { sig } else { libc::SIGKILL };
        signal_child(child_sig);

        // 3. Record signal for exit code (do NOT raise — parent
        //    must stay alive for cleanup).
        TTY_SIGNAL_RECEIVED.store(sig, Ordering::Release);
    }

    // SAFETY: handler is async-signal-safe (tcsetattr, kill, atomics).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        let handler_ptr: extern "C" fn(libc::c_int) = tty_handler;
        sa.sa_sigaction = handler_ptr as usize;
        sa.sa_flags = 0; // No SA_RESTART — poll must return EINTR.
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGQUIT, &sa, std::ptr::null_mut());
    }
}

fn print_usage() {
    eprintln!("usage: arapuca <subcommand> [flags] -- command [args...]");
    eprintln!();
    eprintln!("subcommands:");
    eprintln!("  run        run a command in a process sandbox");
    eprintln!("  image      manage VM images");
    #[cfg(feature = "microvm")]
    eprintln!("  vm         manage micro-VMs");
    eprintln!();
    eprintln!("flags:");
    eprintln!("  -h, --help       show this help");
    eprintln!("  -V, --version    show version");
    eprintln!();
    eprintln!("run `arapuca run --help` for run subcommand flags");
}

fn parse_volume_spec(spec: &str) -> (PathBuf, bool) {
    let lower = spec.to_ascii_lowercase();
    if lower.ends_with(":ro") {
        (PathBuf::from(&spec[..spec.len() - 3]), true)
    } else if lower.ends_with(":rw") {
        (PathBuf::from(&spec[..spec.len() - 3]), false)
    } else {
        (PathBuf::from(spec), false)
    }
}

/// Send a signal to the child process via the stored CHILD_PIDFD
/// (race-free on Linux) or CHILD_PID (fallback on other Unix).
#[cfg(target_os = "linux")]
fn signal_child(sig: libc::c_int) {
    use std::sync::atomic::Ordering;

    let pidfd = CHILD_PIDFD.load(Ordering::Acquire);
    if pidfd >= 0 {
        // SAFETY: pidfd is valid (opened at spawn, not yet closed).
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            );
        }
    } else {
        let pid = CHILD_PID.load(Ordering::Acquire);
        if pid > 0 {
            // SAFETY: kill with valid pid and signal.
            unsafe { libc::kill(pid, sig) };
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn signal_child(sig: libc::c_int) {
    use std::sync::atomic::Ordering;

    let pid = CHILD_PID.load(Ordering::Acquire);
    if pid > 0 {
        // SAFETY: kill with valid pid and signal.
        unsafe { libc::kill(pid, sig) };
    }
}

// ─── --allow-host support ─────────────────────────────────────

#[cfg(target_os = "linux")]
fn parse_allow_host(spec: &str) -> (String, u16) {
    let (host, port_str) = match spec.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !p.is_empty() => (h, p),
        _ => {
            eprintln!(
                "arapuca run: invalid --allow-host: {spec} (expected host:port or *.domain:port)"
            );
            std::process::exit(125);
        }
    };

    // Handle wildcard prefix: *.domain.com → .domain.com (suffix match).
    let (host, is_wildcard) = if let Some(domain) = host.strip_prefix("*.") {
        (domain, true)
    } else if host.contains('*') {
        eprintln!("arapuca run: wildcard must use *.domain format: {host}");
        std::process::exit(125);
    } else {
        (host, false)
    };

    // Strip trailing dot (FQDN normalization).
    let host = host.strip_suffix('.').unwrap_or(host);

    if host.is_empty()
        || host.len() > 253
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        eprintln!("arapuca run: invalid hostname in --allow-host: {host}");
        std::process::exit(125);
    }

    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        eprintln!("arapuca run: invalid hostname in --allow-host: {host}");
        std::process::exit(125);
    }

    let port: u16 = match port_str.parse() {
        Ok(0) => {
            eprintln!("arapuca run: --allow-host port must be 1-65535");
            std::process::exit(125);
        }
        Ok(p) => p,
        Err(_) => {
            eprintln!("arapuca run: invalid port in --allow-host: {port_str}");
            std::process::exit(125);
        }
    };

    let host = if is_wildcard {
        format!(".{}", host.to_ascii_lowercase())
    } else {
        host.to_ascii_lowercase()
    };

    (host, port)
}

#[cfg(target_os = "linux")]
fn fork_connect_proxy(
    allowed_hosts: &[arapuca::bridge::AllowedHost],
    seccomp_debug: bool,
) -> (PathBuf, i32, i32) {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener;

    let proxy_dir = tempfile::Builder::new()
        .prefix("arapuca-connect-proxy-")
        .tempdir_in(std::env::temp_dir())
        .unwrap_or_else(|e| {
            eprintln!("arapuca run: proxy tmpdir: {e}");
            std::process::exit(125);
        });
    let uds_path = proxy_dir.keep().join("connect.sock");

    let listener = UnixListener::bind(&uds_path).unwrap_or_else(|e| {
        eprintln!("arapuca run: proxy bind {}: {e}", uds_path.display());
        std::process::exit(125);
    });

    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe2 with valid array and O_CLOEXEC.
    let ret = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret != 0 {
        eprintln!(
            "arapuca run: proxy pipe: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(125);
    }
    let pipe_read = pipe_fds[0];
    let pipe_write = pipe_fds[1];

    // SAFETY: getpid is always safe.
    let parent_pid = unsafe { libc::getpid() };

    let hosts = allowed_hosts.to_vec();
    let listener_fd = listener.as_raw_fd();

    // SAFETY: single-threaded at this point (before sandbox.launch).
    let child_pid = unsafe { libc::fork() };

    if child_pid < 0 {
        eprintln!(
            "arapuca run: proxy fork: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(125);
    }

    if child_pid == 0 {
        // ── CONNECT proxy child ──────────────────────────────

        // SAFETY: pipe_read is a valid fd from pipe2.
        unsafe { libc::close(pipe_read) };

        // Close all FDs >= 3 except pipe_write and listener_fd.
        unsafe { arapuca::bridge::close_fds_except(&[pipe_write, listener_fd]) };

        // Ignore SIGPIPE so that writing to a broken UDS connection
        // returns EPIPE instead of killing the proxy process.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

        // setsid clears PR_SET_PDEATHSIG, so pdeathsig must be re-set
        // after. The getppid race check below covers the window between
        // setsid and prctl. This differs from the bridge fork (which
        // omits setsid) because the CONNECT proxy is a session leader.
        // SAFETY: setsid is always safe. Tolerate EPERM (already session leader).
        let ret = unsafe { libc::setsid() };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EPERM) {
                eprintln!("arapuca: connect proxy: setsid: {err}");
                unsafe { libc::_exit(1) };
            }
        }

        // SAFETY: prctl with PR_SET_PDEATHSIG.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
            unsafe { libc::_exit(1) };
        }

        // Race check.
        // SAFETY: getppid is always safe.
        if unsafe { libc::getppid() } != parent_pid {
            unsafe { libc::_exit(1) };
        }

        // SAFETY: prctl with PR_SET_NO_NEW_PRIVS.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64) } != 0 {
            unsafe { libc::_exit(1) };
        }

        // SAFETY: prctl with PR_SET_DUMPABLE.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
            unsafe { libc::_exit(1) };
        }

        // Apply Landlock with minimal NSS paths. The proxy needs to
        // read resolver config and load NSS modules, but should not
        // have access to the broader filesystem.
        #[cfg(target_os = "linux")]
        {
            let proxy_read_paths: Vec<std::path::PathBuf> = [
                "/etc/hosts",
                "/etc/nsswitch.conf",
                "/etc/resolv.conf",
                "/etc/gai.conf",
                "/etc/ld.so.cache",
                "/etc/ld.so.conf",
                "/etc/ld.so.conf.d",
                "/etc/services",
                "/etc/ssl",
                "/etc/pki",
                "/etc/ca-certificates",
                "/run/systemd/resolve",
                "/run/nscd",
                "/lib",
                "/lib64",
                "/usr/lib",
                "/usr/lib64",
            ]
            .iter()
            .map(std::path::PathBuf::from)
            .filter(|p| p.exists())
            .collect();

            if !proxy_read_paths.is_empty() {
                let proxy_profile = arapuca::Profile {
                    read_paths: proxy_read_paths,
                    ..Default::default()
                };
                if let Err(e) = arapuca::landlock::apply(&proxy_profile, None) {
                    eprintln!("arapuca: connect proxy: landlock: {e}");
                    unsafe { libc::_exit(1) };
                }
            } else {
                eprintln!("arapuca: connect proxy: no system paths found for Landlock");
                unsafe { libc::_exit(1) };
            }
        }

        // Pre-initialize NSS before seccomp — forces dlopen of all
        // NSS modules. Using an unresolvable FQDN traverses the
        // entire nsswitch hosts chain (files, mymachines, resolve,
        // dns, etc.). NO_NEW_PRIVS does not affect mprotect — only
        // seccomp blocks PROT_EXEC, which is why this must happen
        // before seccomp.
        use std::net::ToSocketAddrs;
        let _ = ("_arapuca-nss-init.invalid.", 0u16).to_socket_addrs();

        #[cfg(seccomp_supported)]
        if let Err(e) = arapuca::bridge::apply_connect_proxy_seccomp(seccomp_debug) {
            eprintln!("arapuca run: proxy seccomp: {e}");
            unsafe { libc::_exit(1) };
        }

        if let Err(e) = arapuca::bridge::connect_proxy_listen(listener, &hosts, pipe_write) {
            eprintln!("arapuca run: proxy: {e}");
        }
        unsafe { libc::_exit(0) };
    }

    // ── Parent ────────────────────────────────────────────────

    drop(listener);
    // SAFETY: pipe_write is a valid fd.
    unsafe { libc::close(pipe_write) };

    // Open pidfd immediately — child PID is guaranteed valid.
    // SAFETY: pidfd_open with valid pid.
    let proxy_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) } as i32;

    // Wait for readiness (5s timeout).
    let mut pfd = libc::pollfd {
        fd: pipe_read,
        events: libc::POLLIN,
        revents: 0,
    };
    let poll_ret = loop {
        // SAFETY: pfd is valid, timeout in ms.
        let ret = unsafe { libc::poll(&mut pfd, 1, 5000) };
        if ret >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break ret;
        }
    };

    // Helper: kill child + clean temp dir on error, then exit.
    let fail_proxy = |msg: &str| -> ! {
        eprintln!("arapuca run: {msg}");
        // SAFETY: child_pid is valid.
        unsafe { libc::kill(child_pid, libc::SIGKILL) };
        let _ = std::fs::remove_dir_all(uds_path.parent().unwrap());
        std::process::exit(125);
    };

    if poll_ret == 0 {
        fail_proxy("proxy readiness timeout (5s)");
    }
    if poll_ret < 0 {
        fail_proxy(&format!("proxy poll: {}", std::io::Error::last_os_error()));
    }

    let mut buf = [0u8; 1];
    let n = loop {
        // SAFETY: pipe_read is valid.
        let ret =
            unsafe { libc::read(pipe_read, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if ret >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break ret;
        }
    };
    // SAFETY: done with pipe_read.
    unsafe { libc::close(pipe_read) };

    if n != 1 {
        fail_proxy("proxy readiness signal failed");
    }

    (uds_path, child_pid, proxy_pidfd)
}

// ─── Image subcommands ─────────────────────────────────────────

fn image_subcommand(args: &[String]) {
    let subcmd = args.first().map(|s| s.as_str());
    match subcmd {
        Some("pull") => image_pull(&args[1..]),
        Some("list") => image_list(),
        Some("rm") => image_rm(&args[1..]),
        #[cfg(feature = "microvm")]
        Some("setup") => image_setup(&args[1..]),
        _ => {
            eprintln!("usage: arapuca image <pull|list|rm|setup>");
            eprintln!();
            eprintln!("  pull [--force|--check] <distro>:<version>");
            eprintln!("                               download and cache an image");
            eprintln!("  list                         show cached images");
            eprintln!("  rm <distro>:<version>        remove a cached image");
            eprintln!("  setup <distro:ver> [flags]   create a setup layer");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "microvm")]
fn image_pull(args: &[String]) {
    let mut force = false;
    let mut check = false;
    let mut spec = None;

    for arg in args {
        match arg.as_str() {
            "--force" => force = true,
            "--check" => check = true,
            s if !s.starts_with('-') && spec.is_none() => spec = Some(s),
            _ => {
                eprintln!("usage: arapuca image pull [--force|--check] <distro>:<version>");
                std::process::exit(1);
            }
        }
    }

    let spec = match spec {
        Some(s) => s,
        None => {
            eprintln!("usage: arapuca image pull [--force|--check] <distro>:<version>");
            std::process::exit(1);
        }
    };

    if force && check {
        eprintln!("--force and --check are mutually exclusive");
        std::process::exit(1);
    }

    let (distro, version) = match spec.split_once(':') {
        Some((d, v)) if !d.is_empty() && !v.is_empty() => (d, v),
        _ => {
            eprintln!("invalid image specifier: {spec} (expected distro:version)");
            std::process::exit(1);
        }
    };

    let source = arapuca::ImageSource::Distro {
        name: distro.into(),
        version: version.into(),
    };
    let opts = arapuca::images::ResolveOptions { force, check };

    match arapuca::images::resolve(&source, &opts) {
        Ok(cached) => {
            println!("{}", cached.path.display());
        }
        Err(e) => {
            eprintln!("arapuca: image pull failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(feature = "microvm"))]
fn image_pull(_args: &[String]) {
    eprintln!("arapuca: image pull requires the 'microvm' feature");
    eprintln!("rebuild with: cargo build --features microvm");
    std::process::exit(1);
}

fn image_list() {
    match arapuca::images::cache::list() {
        Ok(images) => {
            if images.is_empty() {
                println!("no cached images");
                return;
            }
            for (name, cached) in &images {
                let size = std::fs::metadata(&cached.path)
                    .map(|m| m.len() / (1024 * 1024))
                    .unwrap_or(0);
                let indent = if name.contains(".setup-") { "  " } else { "" };
                println!(
                    "{indent}{name}  {size}MB  root={} fs={}",
                    cached.metadata.root_device, cached.metadata.fstype,
                );
            }
        }
        Err(e) => {
            eprintln!("arapuca: image list failed: {e}");
            std::process::exit(1);
        }
    }
}

fn image_rm(args: &[String]) {
    let spec = match args.first() {
        Some(s) => s,
        None => {
            eprintln!("usage: arapuca image rm <name>");
            std::process::exit(1);
        }
    };

    // Accept both "distro:version" and cache name formats.
    let cache_name = if let Some((distro, version)) = spec.split_once(':') {
        if distro.is_empty() || version.is_empty() {
            eprintln!("invalid image specifier: {spec} (expected distro:version)");
            std::process::exit(1);
        }
        let arch = std::env::consts::ARCH;
        format!("{distro}-{version}-{arch}")
    } else {
        spec.clone()
    };

    match arapuca::images::cache::remove(&cache_name) {
        Ok(true) => println!("removed {cache_name}"),
        Ok(false) => {
            eprintln!("image not found: {cache_name}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("arapuca: image rm failed: {e}");
            std::process::exit(1);
        }
    }
}

// ─── Image setup ──────────────────────────────────────────────

#[cfg(feature = "microvm")]
fn image_setup(args: &[String]) {
    use arapuca::platform::{MicroVm, Sandbox};

    let mut image_spec = None;
    let mut run_cmd = None;
    let mut script_path = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--run" => {
                i += 1;
                run_cmd = Some(args.get(i).cloned().unwrap_or_default());
            }
            "--script" => {
                i += 1;
                script_path = Some(args.get(i).cloned().unwrap_or_default());
            }
            s if !s.starts_with('-') && image_spec.is_none() => {
                image_spec = Some(s.to_string());
            }
            _ => {
                eprintln!("unknown flag: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let spec = match image_spec {
        Some(s) => s,
        None => {
            eprintln!(
                "usage: arapuca image setup <distro:version> --run '<cmd>' | --script <path>"
            );
            std::process::exit(1);
        }
    };

    let script = match (run_cmd, script_path) {
        (Some(cmd), None) => cmd,
        (None, Some(path)) => match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("arapuca: cannot read script {path}: {e}");
                std::process::exit(1);
            }
        },
        (Some(_), Some(_)) => {
            eprintln!("arapuca: --run and --script are mutually exclusive");
            std::process::exit(1);
        }
        (None, None) => {
            eprintln!(
                "usage: arapuca image setup <distro:version> --run '<cmd>' | --script <path>"
            );
            std::process::exit(1);
        }
    };

    let (distro, version) = match spec.split_once(':') {
        Some((d, v)) if !d.is_empty() && !v.is_empty() => (d, v),
        _ => {
            eprintln!("invalid image specifier: {spec} (expected distro:version)");
            std::process::exit(1);
        }
    };

    let image_source = arapuca::ImageSource::Distro {
        name: distro.into(),
        version: version.into(),
    };

    // Resolve the base image (pull if needed).
    let cached = match arapuca::images::resolve(&image_source, &Default::default()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("arapuca: image resolve failed: {e}");
            std::process::exit(1);
        }
    };

    let arch = std::env::consts::ARCH;
    let base_name = format!("{distro}-{version}-{arch}");
    let base_sha256 = cached.metadata.sha256.as_deref();

    // Check if a setup layer already exists.
    match arapuca::images::setup::lookup(&base_name, &script, base_sha256) {
        Ok(Some(layer)) => {
            println!("{}", layer.path.display());
            eprintln!("setup layer already exists");
            return;
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("arapuca: setup lookup failed: {e}");
            std::process::exit(1);
        }
    }

    // Build a minimal config: no host mounts, networking enabled.
    let profile = arapuca::Profile {
        isolation: arapuca::Isolation::MicroVm(arapuca::MicroVmConfig {
            image: image_source.clone(),
            cpus: 2,
            mem_mb: 2048,
            write_files: Vec::new(),
        }),
        use_netns: false,
        ..Default::default()
    };

    let config = arapuca::Config {
        profile,
        socket_dir: std::env::temp_dir(),
        task_id: format!("setup-{distro}-{version}"),
        phase: "image-setup".into(),
        work_dir: None,
        #[cfg(unix)]
        stdin: None,
        #[cfg(unix)]
        stdout: None,
        #[cfg(unix)]
        stderr: None,
        #[cfg(unix)]
        extra_fds: Vec::new(),
        #[cfg(unix)]
        tty: false,
        network_proxy_socket: None,
        env: Vec::new(),
        audit_sink: None,
        audit_verbosity: arapuca::audit::AuditVerbosity::Standard,
        audit_principal: None,
        audit_correlation_id: None,
    };

    eprintln!("running setup VM...");

    let sandbox = MicroVm::new().unwrap_or_else(|e| {
        eprintln!("arapuca: microvm: {e}");
        std::process::exit(125);
    });

    // Launch setup VM with the setup script as the command.
    let mut process = match sandbox.launch(&config, "/bin/sh", &["-c", &script]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("arapuca: setup VM launch failed: {e}");
            std::process::exit(125);
        }
    };

    let status = match process.wait() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("arapuca: setup VM wait failed: {e}");
            std::process::exit(125);
        }
    };

    let exit_code = status.code().unwrap_or(1);

    // Save the overlay path before cleanup destroys the temp dir.
    let vm_overlay = process.tmp_dir().join("vm").join("disk.qcow2");

    if exit_code != 0 {
        process.cleanup();
        eprintln!("arapuca: setup command failed (exit {exit_code})");
        eprintln!("no setup layer was created");
        std::process::exit(exit_code);
    }

    // Success — cache the overlay as a setup layer.
    let result = arapuca::images::setup::store(
        &base_name,
        &script,
        &vm_overlay,
        &cached.metadata,
        base_sha256,
    );
    process.cleanup();

    match result {
        Ok(layer) => {
            eprintln!("setup layer created");
            println!("{}", layer.path.display());
        }
        Err(e) => {
            eprintln!("arapuca: failed to cache setup layer: {e}");
            std::process::exit(1);
        }
    }
}

// ─── VM subcommands ────────────────────────────────────────────

#[cfg(feature = "microvm")]
fn vm_subcommand(args: &[String]) {
    match args.first().map(|s| s.as_str()) {
        Some("run") => vm_run(&args[1..]),
        Some("start") => vm_start(&args[1..]),
        Some("exec") => vm_exec(&args[1..]),
        Some("stop") => vm_stop(&args[1..]),
        Some("list") | Some("ls") => vm_list(),
        Some("rm") | Some("remove") => vm_rm(&args[1..]),
        Some("prune") => vm_prune(),
        Some("reset") => vm_reset(&args[1..]),
        _ => {
            eprintln!("usage: arapuca vm <command>");
            eprintln!();
            eprintln!("commands:");
            eprintln!("  run [flags] -- command [args...]   run a command in an ephemeral VM");
            eprintln!("  start [flags]                      start a persistent VM");
            eprintln!("  exec <name> [flags] -- cmd [args]  exec in a running VM");
            eprintln!("  stop <name> [--force] [--timeout N] stop a VM");
            eprintln!("  list                               list VMs");
            eprintln!("  rm <name>                          remove a stopped VM");
            eprintln!("  prune                              clean up stale VM state");
            eprintln!("  reset <name>                       recreate overlay from base");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "microvm")]
fn vm_start(args: &[String]) {
    let mut image: Option<String> = None;
    let mut name: Option<String> = None;
    let mut cpus: u32 = 2;
    let mut mem_mb: u32 = 2048;
    let mut net = false;
    let mut volumes: Vec<arapuca::vm::VolumeSpec> = Vec::new();
    let mut max_lifetime: Option<u64> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--image" => {
                i += 1;
                image = Some(
                    args.get(i)
                        .unwrap_or_else(|| {
                            eprintln!("--image requires a value");
                            std::process::exit(125);
                        })
                        .clone(),
                );
            }
            "--name" => {
                i += 1;
                name = Some(
                    args.get(i)
                        .unwrap_or_else(|| {
                            eprintln!("--name requires a value");
                            std::process::exit(125);
                        })
                        .clone(),
                );
            }
            "--cpus" => {
                i += 1;
                cpus = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                    eprintln!("--cpus requires a positive integer");
                    std::process::exit(125);
                });
                if cpus == 0 {
                    eprintln!("--cpus must be > 0");
                    std::process::exit(125);
                }
            }
            "--mem" => {
                i += 1;
                mem_mb = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                    eprintln!("--mem requires a positive integer");
                    std::process::exit(125);
                });
                if mem_mb == 0 {
                    eprintln!("--mem must be > 0");
                    std::process::exit(125);
                }
            }
            "--net" => {
                net = true;
            }
            "-v" | "--volume" => {
                i += 1;
                let spec = args.get(i).unwrap_or_else(|| {
                    eprintln!("-v requires host:guest[:opts]");
                    std::process::exit(125);
                });
                let parts: Vec<&str> = spec.splitn(3, ':').collect();
                if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
                    eprintln!("invalid volume: {spec} (expected host:guest[:opts])");
                    std::process::exit(125);
                }
                let opts = parts.get(2).unwrap_or(&"").to_lowercase();
                volumes.push(arapuca::vm::VolumeSpec {
                    host: parts[0].to_string(),
                    guest: parts[1].to_string(),
                    read_only: opts.contains("ro"),
                });
            }
            "--max-lifetime" => {
                i += 1;
                max_lifetime =
                    Some(args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                        eprintln!("--max-lifetime requires a positive integer");
                        std::process::exit(125);
                    }));
            }
            other => {
                eprintln!("unknown flag: {other}");
                eprintln!("run 'arapuca vm start --help' for usage");
                std::process::exit(125);
            }
        }
        i += 1;
    }

    // --image is required on first start, optional on restart.
    let vm_name = name.unwrap_or_else(|| {
        let mut buf = [0u8; 8];
        // SAFETY: getrandom with valid buffer and no flags.
        let ret = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
        if ret != buf.len() as isize {
            eprintln!(
                "arapuca: getrandom failed for VM name: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(1);
        }
        format!(
            "vm-{}",
            buf.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    });

    // Check if this is a restart (VM dir exists but not running).
    let is_restart = arapuca::vm::state::vm_dir(&vm_name)
        .map(|d| d.exists())
        .unwrap_or(false);

    let image_source = if let Some(img) = &image {
        parse_image_source(img)
    } else if is_restart {
        match arapuca::vm::state::VmConfig::load(&vm_name) {
            Ok(cfg) => parse_image_source(&cfg.image),
            Err(e) => {
                eprintln!("arapuca: cannot load VM config: {e}");
                std::process::exit(125);
            }
        }
    } else {
        eprintln!("--image is required for new VMs");
        std::process::exit(125);
    };

    // Default max-lifetime: 24 hours.
    let max_lifetime = max_lifetime.or(Some(86400));

    let opts = arapuca::vm::StartOpts {
        name: vm_name,
        image: image_source,
        cpus,
        mem_mb,
        net,
        volumes,
        max_lifetime,
    };

    match arapuca::vm::start(&opts) {
        Ok(result) => {
            println!("{} {}", result.name, result.pid);
        }
        Err(e) => {
            eprintln!("arapuca: vm start failed: {e}");
            std::process::exit(125);
        }
    }
}

#[cfg(feature = "microvm")]
fn vm_list() {
    match arapuca::vm::state::list_vms() {
        Ok(vms) => {
            if vms.is_empty() {
                println!("no VMs");
                return;
            }
            for vm in &vms {
                let status = if vm.running { "running" } else { "stopped" };
                let pid = vm.pid.map(|p| p.to_string()).unwrap_or_default();
                let size_mb = vm.overlay_size_bytes / (1024 * 1024);
                println!(
                    "{:<20} {:<10} {:<8} {:<10} {}MB",
                    vm.name, status, pid, vm.image, size_mb
                );
            }
        }
        Err(e) => {
            eprintln!("arapuca: vm list failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "microvm")]
fn vm_exec(args: &[String]) {
    let vm_name = match args.first() {
        Some(name) if !name.starts_with('-') => name.clone(),
        _ => {
            eprintln!("usage: arapuca vm exec <name> [--env K=V] [--user U] -- cmd [args]");
            std::process::exit(125);
        }
    };

    let rest = &args[1..];
    let mut env_vars: Vec<String> = Vec::new();
    let mut user = "root".to_string();
    let mut tty = false;

    let sep_pos = rest.iter().position(|a| a == "--");
    let flag_args = match sep_pos {
        Some(pos) => &rest[..pos],
        None => rest,
    };
    let cmd_args: &[String] = match sep_pos {
        Some(pos) if pos + 1 < rest.len() => &rest[pos + 1..],
        _ => {
            eprintln!("usage: arapuca vm exec <name> [flags] -- command [args...]");
            std::process::exit(125);
        }
    };

    let mut i = 0;
    while i < flag_args.len() {
        match flag_args[i].as_str() {
            "--env" => {
                i += 1;
                let kv = flag_args.get(i).unwrap_or_else(|| {
                    eprintln!("--env requires KEY=VALUE");
                    std::process::exit(125);
                });
                env_vars.push(kv.clone());
            }
            "--user" => {
                i += 1;
                user = flag_args
                    .get(i)
                    .unwrap_or_else(|| {
                        eprintln!("--user requires a value");
                        std::process::exit(125);
                    })
                    .clone();
            }
            "-t" | "--tty" => {
                tty = true;
            }
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(125);
            }
        }
        i += 1;
    }

    if !arapuca::vm::state::is_running(&vm_name).unwrap_or(false) {
        eprintln!("arapuca: VM '{vm_name}' is not running");
        std::process::exit(1);
    }

    let config = match arapuca::vm::state::VmConfig::load(&vm_name) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("arapuca: cannot load VM config: {e}");
            std::process::exit(1);
        }
    };

    let sock_path = match arapuca::vm::state::agent_sock_path(&vm_name) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("arapuca: {e}");
            std::process::exit(1);
        }
    };

    // Build a minimal base env (do NOT forward the host environment).
    // Matches podman/docker exec semantics.
    let home = if user == "root" {
        "/root".to_string()
    } else {
        format!("/home/{user}")
    };
    let term = std::env::var("TERM")
        .unwrap_or_else(|_| "xterm".to_string())
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c))
        .take(64)
        .collect::<String>();

    let mut env_map = std::collections::HashMap::new();
    env_map.insert("HOME".to_string(), home);
    env_map.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    env_map.insert("TERM".to_string(), term);
    env_map.insert("LANG".to_string(), "C.UTF-8".to_string());

    // Explicit --env values override base vars (filtered for dangerous vars).
    let explicit: Vec<(String, String)> = env_vars
        .iter()
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect();
    let filtered = arapuca::env::filter_caller_env(&explicit);
    for (k, v) in filtered.passed {
        env_map.insert(k, v);
    }

    let filtered_env: Vec<String> = env_map
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();

    if tty && !std::io::stdin().is_terminal() {
        eprintln!("arapuca: -t requires a terminal on stdin");
        std::process::exit(125);
    }

    let cmd = cmd_args[0].as_str();
    let cmd_rest: Vec<String> = cmd_args[1..].to_vec();

    let exit_code = match arapuca::vm::exec::exec(
        &sock_path,
        &config.nonce,
        cmd,
        &cmd_rest,
        &filtered_env,
        &user,
        tty,
    ) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("arapuca: vm exec failed: {e}");
            125
        }
    };

    std::process::exit(exit_code);
}

#[cfg(feature = "microvm")]
fn vm_stop(args: &[String]) {
    let mut name: Option<String> = None;
    let mut force = false;
    let mut timeout_secs: u64 = 10;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--force" | "-f" => force = true,
            "--timeout" => {
                i += 1;
                timeout_secs = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                    eprintln!("--timeout requires a positive integer");
                    std::process::exit(125);
                });
            }
            s if !s.starts_with('-') && name.is_none() => {
                name = Some(s.to_string());
            }
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(125);
            }
        }
        i += 1;
    }

    let vm_name = name.unwrap_or_else(|| {
        eprintln!("usage: arapuca vm stop <name> [--force] [--timeout N]");
        std::process::exit(125);
    });

    if !arapuca::vm::state::is_running(&vm_name).unwrap_or(false) {
        eprintln!("VM '{vm_name}' is not running");
        std::process::exit(1);
    }

    // Send SIGTERM first (gives krun a chance to clean up), then
    // SIGKILL after the timeout. Graceful guest-side shutdown via
    // the agent is not possible with standard libkrun (only
    // libkrun-efi supports krun_get_shutdown_eventfd).
    if let Ok(Some(pid)) = arapuca::vm::state::read_lock_pid(&vm_name) {
        // Open pidfd once to pin the process for both SIGTERM and SIGKILL.
        // SAFETY: pidfd_open with valid pid.
        let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as i32, 0) };
        if ret >= 0 {
            let pidfd = ret as libc::c_int;
            let sig = if force { libc::SIGKILL } else { libc::SIGTERM };
            // SAFETY: pidfd_send_signal with valid pidfd.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd,
                    sig,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                );
            }

            for _ in 0..(timeout_secs * 10) {
                if !arapuca::vm::state::is_running(&vm_name).unwrap_or(true) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }

            if !force && arapuca::vm::state::is_running(&vm_name).unwrap_or(false) {
                // SAFETY: pidfd_send_signal with valid pidfd.
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd,
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0u32,
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }

            // SAFETY: pidfd is a valid open fd.
            unsafe { libc::close(pidfd) };
        }
    }

    if let Ok(config) = arapuca::vm::state::VmConfig::load(&vm_name) {
        kill_passt_from_config(&config);
    }

    if arapuca::vm::state::is_running(&vm_name).unwrap_or(false) {
        eprintln!("arapuca: VM '{vm_name}' did not stop");
        std::process::exit(1);
    }

    println!("stopped {vm_name}");
}

#[cfg(feature = "microvm")]
fn kill_passt_from_config(config: &arapuca::vm::state::VmConfig) {
    if let Some(passt_pid) = config.passt_pid {
        // Open pidfd first to pin the process, then verify /proc/comm.
        // SAFETY: pidfd_open with valid pid.
        let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, passt_pid as i32, 0) };
        if ret < 0 {
            return;
        }
        let pidfd = ret as libc::c_int;

        let comm = format!("/proc/{passt_pid}/comm");
        let is_passt = std::fs::read_to_string(&comm)
            .map(|c| c.trim() == "passt")
            .unwrap_or(false);

        if is_passt {
            // SAFETY: pidfd_send_signal with valid pidfd.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd,
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                );
            }
        }
        // SAFETY: pidfd is a valid open fd.
        unsafe { libc::close(pidfd) };
    }
}

#[cfg(feature = "microvm")]
fn vm_rm(args: &[String]) {
    let name = match args.first() {
        Some(n) => n,
        None => {
            eprintln!("usage: arapuca vm rm <name>");
            std::process::exit(125);
        }
    };

    match arapuca::vm::state::remove_vm(name) {
        Ok(()) => println!("removed {name}"),
        Err(e) => {
            eprintln!("arapuca: vm rm: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "microvm")]
fn vm_prune() {
    match arapuca::vm::state::prune_stale() {
        Ok(pruned) => {
            if pruned.is_empty() {
                println!("nothing to prune");
            } else {
                for name in &pruned {
                    println!("pruned {name}");
                }
            }
        }
        Err(e) => {
            eprintln!("arapuca: vm prune: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "microvm")]
fn vm_reset(args: &[String]) {
    let name = match args.first() {
        Some(n) => n,
        None => {
            eprintln!("usage: arapuca vm reset <name>");
            std::process::exit(125);
        }
    };

    if arapuca::vm::state::is_running(name).unwrap_or(false) {
        eprintln!("arapuca: VM '{name}' is running, stop it first");
        std::process::exit(1);
    }

    // Load config to find the base image.
    let config = match arapuca::vm::state::VmConfig::load(name) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("arapuca: cannot load VM config: {e}");
            std::process::exit(1);
        }
    };

    let image_source = parse_image_source(&config.image);
    let cached = match arapuca::images::resolve(&image_source, &Default::default()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("arapuca: image resolve: {e}");
            std::process::exit(1);
        }
    };

    // Remove old overlay and create fresh one.
    let overlay = match arapuca::vm::state::overlay_path(name) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("arapuca: {e}");
            std::process::exit(1);
        }
    };
    if overlay.exists() {
        if let Err(e) = std::fs::remove_file(&overlay) {
            eprintln!("arapuca: remove overlay: {e}");
            std::process::exit(1);
        }
    }

    let vm_dir = match arapuca::vm::state::vm_dir(name) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("arapuca: {e}");
            std::process::exit(1);
        }
    };
    match arapuca::images::overlay::create_overlay(&cached.path, &vm_dir) {
        Ok(_) => println!("reset {name}"),
        Err(e) => {
            eprintln!("arapuca: create overlay: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "microvm")]
fn parse_image_source(spec: &str) -> arapuca::ImageSource {
    if spec.contains('/') || spec.ends_with(".qcow2") || spec.ends_with(".raw") {
        arapuca::ImageSource::Path(PathBuf::from(spec))
    } else if let Some((distro, version)) = spec.split_once(':') {
        if distro.is_empty() || version.is_empty() {
            eprintln!("invalid image: {spec} (expected distro:version or path)");
            std::process::exit(125);
        }
        arapuca::ImageSource::Distro {
            name: distro.to_string(),
            version: version.to_string(),
        }
    } else {
        eprintln!("invalid image: {spec} (expected distro:version or path)");
        std::process::exit(125);
    }
}

#[cfg(feature = "microvm")]
fn vm_run(args: &[String]) {
    use arapuca::platform::{MicroVm, Sandbox};

    let mut image: Option<String> = None;
    let mut cpus: u32 = 2;
    let mut mem_mb: u32 = 2048;
    let mut volumes: Vec<(String, String, String)> = Vec::new(); // host, guest, opts
    let mut net = false;
    let mut env: Vec<(String, String)> = Vec::new();
    let mut write_files: Vec<(String, String)> = Vec::new(); // host, guest
    let mut timeout: Option<u64> = None;
    let mut task_id: Option<String> = None;

    // Find -- separator.
    let sep_pos = args.iter().position(|a| a == "--");
    let flag_args = match sep_pos {
        Some(pos) => &args[..pos],
        None => args,
    };
    let cmd_args: &[String] = match sep_pos {
        Some(pos) if pos + 1 < args.len() => &args[pos + 1..],
        _ => &[],
    };

    // Parse flags.
    let mut i = 0;
    while i < flag_args.len() {
        match flag_args[i].as_str() {
            "--image" => {
                i += 1;
                image = Some(
                    flag_args
                        .get(i)
                        .unwrap_or_else(|| {
                            eprintln!("--image requires a value");
                            std::process::exit(125);
                        })
                        .clone(),
                );
            }
            "--cpus" => {
                i += 1;
                cpus = flag_args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("--cpus requires a positive integer");
                        std::process::exit(125);
                    });
                if cpus == 0 {
                    eprintln!("--cpus must be > 0");
                    std::process::exit(125);
                }
            }
            "--mem" => {
                i += 1;
                mem_mb = flag_args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("--mem requires a positive integer");
                        std::process::exit(125);
                    });
                if mem_mb == 0 {
                    eprintln!("--mem must be > 0");
                    std::process::exit(125);
                }
            }
            "-v" | "--volume" => {
                i += 1;
                let spec = flag_args.get(i).unwrap_or_else(|| {
                    eprintln!("-v requires host:guest[:opts]");
                    std::process::exit(125);
                });
                let parts: Vec<&str> = spec.splitn(3, ':').collect();
                if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
                    eprintln!("invalid volume: {spec} (expected host:guest[:opts])");
                    std::process::exit(125);
                }
                volumes.push((
                    parts[0].to_string(),
                    parts[1].to_string(),
                    parts.get(2).unwrap_or(&"").to_string(),
                ));
            }
            "--net" => {
                net = true;
            }
            "--env" => {
                i += 1;
                let kv = flag_args.get(i).unwrap_or_else(|| {
                    eprintln!("--env requires KEY=VALUE");
                    std::process::exit(125);
                });
                if let Some((k, v)) = kv.split_once('=') {
                    env.push((k.to_string(), v.to_string()));
                } else {
                    eprintln!("invalid --env: {kv} (expected KEY=VALUE)");
                    std::process::exit(125);
                }
            }
            "--write-file" => {
                i += 1;
                let spec = flag_args.get(i).unwrap_or_else(|| {
                    eprintln!("--write-file requires host_path:guest_path");
                    std::process::exit(125);
                });
                if let Some((host, guest)) = spec.split_once(':') {
                    if host.is_empty() || guest.is_empty() {
                        eprintln!("invalid --write-file: {spec}");
                        std::process::exit(125);
                    }
                    // Validate host file.
                    let meta = match std::fs::metadata(host) {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("--write-file: {host}: {e}");
                            std::process::exit(125);
                        }
                    };
                    if !meta.is_file() {
                        eprintln!("--write-file: {host}: not a regular file");
                        std::process::exit(125);
                    }
                    if meta.len() > 1024 * 1024 {
                        eprintln!("--write-file: {host}: file too large (max 1MB)");
                        std::process::exit(125);
                    }
                    if !guest.starts_with('/') {
                        eprintln!("--write-file: guest path must be absolute: {guest}");
                        std::process::exit(125);
                    }
                    write_files.push((host.to_string(), guest.to_string()));
                } else {
                    eprintln!("invalid --write-file: {spec} (expected host:guest)");
                    std::process::exit(125);
                }
            }
            "--timeout" => {
                i += 1;
                let secs: u64 = flag_args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("--timeout requires a positive integer (seconds)");
                        std::process::exit(125);
                    });
                if secs == 0 {
                    eprintln!("--timeout must be > 0");
                    std::process::exit(125);
                }
                timeout = Some(secs);
            }
            "--task-id" => {
                i += 1;
                task_id = Some(
                    flag_args
                        .get(i)
                        .unwrap_or_else(|| {
                            eprintln!("--task-id requires a value");
                            std::process::exit(125);
                        })
                        .clone(),
                );
            }
            other => {
                eprintln!("unknown flag: {other}");
                eprintln!("run 'arapuca vm' for usage");
                std::process::exit(125);
            }
        }
        i += 1;
    }

    let image = image.unwrap_or_else(|| {
        eprintln!("--image is required");
        std::process::exit(125);
    });

    // Parse image specifier.
    let image_source =
        if image.contains('/') || image.ends_with(".qcow2") || image.ends_with(".raw") {
            arapuca::ImageSource::Path(PathBuf::from(&image))
        } else if let Some((distro, version)) = image.split_once(':') {
            if distro.is_empty() || version.is_empty() {
                eprintln!("invalid image: {image} (expected distro:version or path)");
                std::process::exit(125);
            }
            arapuca::ImageSource::Distro {
                name: distro.to_string(),
                version: version.to_string(),
            }
        } else {
            eprintln!("invalid image: {image} (expected distro:version or path)");
            std::process::exit(125);
        };

    // Build profile.
    let mut read_paths = Vec::new();
    let mut write_paths = Vec::new();

    for (host, _guest, opts) in &volumes {
        let opts_lower = opts.to_lowercase();

        // SELinux relabeling.
        #[cfg(target_os = "linux")]
        if opts.contains('z') || opts.contains('Z') {
            apply_selinux_label(host);
        }

        if opts_lower.contains("ro") {
            read_paths.push(PathBuf::from(host));
        } else {
            write_paths.push(PathBuf::from(host));
        }
    }

    let task = task_id.unwrap_or_else(|| format!("vm-{}", std::process::id()));

    // Read host files and build GuestFile entries.
    let guest_files: Vec<arapuca::GuestFile> = write_files
        .iter()
        .map(|(host, guest)| {
            let content = match std::fs::read_to_string(host) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("arapuca: cannot read {host}: {e}");
                    std::process::exit(125);
                }
            };
            arapuca::GuestFile {
                path: guest.clone(),
                content,
                permissions: None,
            }
        })
        .collect();

    let profile = arapuca::Profile {
        isolation: arapuca::Isolation::MicroVm(arapuca::MicroVmConfig {
            image: image_source,
            cpus,
            mem_mb,
            write_files: guest_files,
        }),
        read_paths,
        write_paths,
        use_netns: !net,
        ..Default::default()
    };

    let config = arapuca::Config {
        profile,
        socket_dir: std::env::temp_dir(),
        task_id: task,
        phase: "vm-run".into(),
        work_dir: None,
        #[cfg(unix)]
        stdin: None,
        #[cfg(unix)]
        stdout: None,
        #[cfg(unix)]
        stderr: None,
        #[cfg(unix)]
        extra_fds: Vec::new(),
        #[cfg(unix)]
        tty: false,
        network_proxy_socket: None,
        env,
        audit_sink: None,
        audit_verbosity: arapuca::audit::AuditVerbosity::Standard,
        audit_principal: None,
        audit_correlation_id: None,
    };

    // Build the command string.
    let cmd = cmd_args.first().map(|s| s.as_str()).unwrap_or("");
    let cmd_rest: Vec<&str> = cmd_args.iter().skip(1).map(|s| s.as_str()).collect();

    // Launch.
    let sandbox = MicroVm::new().unwrap_or_else(|e| {
        eprintln!("arapuca: microvm: {e}");
        std::process::exit(125);
    });

    if let Err(e) = sandbox.available() {
        eprintln!("arapuca: microvm not available: {e}");
        std::process::exit(125);
    }

    let mut process = match sandbox.launch(&config, cmd, &cmd_rest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("arapuca: vm launch failed: {e}");
            std::process::exit(125);
        }
    };

    // Forward SIGINT/SIGTERM to the VM child for graceful shutdown.
    install_signal_forwarder(process.pid() as i32);

    // Wait with optional timeout. The done flag prevents the
    // timer thread from killing a recycled PID after the VM exits.
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    if let Some(secs) = timeout {
        let done_clone = std::sync::Arc::clone(&done);
        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            std::thread::sleep(std::time::Duration::from_secs(secs));
            if done_clone.load(Ordering::Acquire) {
                return;
            }
            eprintln!("arapuca: timeout ({secs}s), killing VM");
            signal_child(libc::SIGTERM);
            std::thread::sleep(std::time::Duration::from_secs(5));
            if done_clone.load(Ordering::Acquire) {
                return;
            }
            signal_child(libc::SIGKILL);
        });
    }

    let status = process.wait();
    done.store(true, std::sync::atomic::Ordering::Release);
    CHILD_PID.store(0, std::sync::atomic::Ordering::Release);
    let pidfd = CHILD_PIDFD.swap(-1, std::sync::atomic::Ordering::AcqRel);
    if pidfd >= 0 {
        // SAFETY: pidfd is a valid open file descriptor.
        unsafe { libc::close(pidfd) };
    }

    let exit_code = match status {
        #[allow(clippy::manual_unwrap_or)]
        Ok(s) => {
            if let Some(code) = s.code() {
                code
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    128 + s.signal().unwrap_or(9)
                }
                #[cfg(not(unix))]
                {
                    137
                }
            }
        }
        Err(e) => {
            eprintln!("arapuca: wait failed: {e}");
            125
        }
    };

    process.cleanup();
    std::process::exit(exit_code);
}

#[cfg(unix)]
static CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

#[cfg(unix)]
static CHILD_PIDFD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Store the child PID and open a pidfd for race-free signal delivery.
/// Does NOT install signal handlers — use `install_signal_forwarder`
/// or `install_tty_signal_handler` after this.
#[cfg(unix)]
fn store_child_pid(child_pid: i32) {
    use std::sync::atomic::Ordering;
    CHILD_PID.store(child_pid, Ordering::Release);

    #[cfg(target_os = "linux")]
    {
        // SAFETY: pidfd_open with valid pid.
        let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) };
        if ret >= 0 {
            CHILD_PIDFD.store(ret as i32, Ordering::Release);
        }
    }
}

/// Install signal handlers that forward SIGINT/SIGTERM to a child
/// process. First signal sends SIGTERM for graceful shutdown; second
/// signal sends SIGKILL. Also stores child PID/pidfd.
///
/// Linux: uses pidfd for race-free signal delivery with kill() fallback.
/// Other Unix: uses plain kill() (no pidfd on macOS/BSD).
#[cfg(target_os = "linux")]
fn install_signal_forwarder(child_pid: i32) {
    use std::sync::atomic::{AtomicI32, Ordering};

    static SIGNAL_COUNT: AtomicI32 = AtomicI32::new(0);

    CHILD_PID.store(child_pid, Ordering::Release);

    // Open pidfd immediately — the child PID is guaranteed valid
    // (just spawned, not yet waited). The pidfd prevents PID
    // recycling races in the signal handler.
    // SAFETY: pidfd_open with valid pid.
    let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) };
    if ret >= 0 {
        CHILD_PIDFD.store(ret as i32, Ordering::Release);
    }

    SIGNAL_COUNT.store(0, Ordering::Release);

    extern "C" fn handler(_sig: libc::c_int) {
        let count = SIGNAL_COUNT.fetch_add(1, Ordering::AcqRel);
        let sig = if count == 0 {
            libc::SIGTERM
        } else {
            libc::SIGKILL
        };

        // Prefer pidfd (race-free). Fall back to kill() if pidfd
        // was unavailable (pre-5.3 kernel, EMFILE, etc.).
        let pidfd = CHILD_PIDFD.load(Ordering::Acquire);
        if pidfd >= 0 {
            // SAFETY: pidfd_send_signal is a syscall (async-signal-safe).
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd,
                    sig,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                );
            }
        } else {
            let pid = CHILD_PID.load(Ordering::Acquire);
            if pid > 0 {
                // SAFETY: kill is async-signal-safe.
                unsafe { libc::kill(pid, sig) };
            }
        }
    }

    // Use sigaction instead of signal to avoid handler-reset-on-
    // delivery (System V semantics). sigaction keeps the handler
    // installed across invocations.
    // SAFETY: handler is async-signal-safe (only atomics + kill).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        let handler_ptr: extern "C" fn(libc::c_int) = handler;
        sa.sa_sigaction = handler_ptr as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

/// Non-Linux Unix variant: plain kill() without pidfd.
#[cfg(all(unix, not(target_os = "linux")))]
fn install_signal_forwarder(child_pid: i32) {
    use std::sync::atomic::{AtomicI32, Ordering};

    static SIGNAL_COUNT: AtomicI32 = AtomicI32::new(0);

    CHILD_PID.store(child_pid, Ordering::Release);
    SIGNAL_COUNT.store(0, Ordering::Release);

    extern "C" fn handler(_sig: libc::c_int) {
        let count = SIGNAL_COUNT.fetch_add(1, Ordering::AcqRel);
        let sig = if count == 0 {
            libc::SIGTERM
        } else {
            libc::SIGKILL
        };
        let pid = CHILD_PID.load(Ordering::Acquire);
        if pid > 0 {
            // SAFETY: kill is async-signal-safe.
            unsafe { libc::kill(pid, sig) };
        }
    }

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        let handler_ptr: extern "C" fn(libc::c_int) = handler;
        sa.sa_sigaction = handler_ptr as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

#[cfg(all(feature = "microvm", target_os = "linux"))]
fn apply_selinux_label(path: &str) {
    // Reject dangerous paths that should never be relabeled.
    let canonical = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("warning: cannot resolve {path} for SELinux relabel: {e}");
            return;
        }
    };
    let canon_str = canonical.to_string_lossy();
    let dangerous = [
        "/", "/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/dev", "/proc",
        "/sys", "/run", "/tmp",
    ];
    if dangerous
        .iter()
        .any(|d| canon_str == *d || canon_str.starts_with(&format!("{d}/")))
    {
        eprintln!("warning: refusing to relabel {path} (system directory)");
        return;
    }

    let enforcing = std::fs::read_to_string("/sys/fs/selinux/enforce")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    if !enforcing {
        return;
    }

    // Use the canonicalized path to prevent TOCTOU symlink swaps.
    let status = std::process::Command::new("chcon")
        .args(["-R", "-t", "svirt_sandbox_file_t", &*canon_str])
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!(
            "warning: chcon failed on {path} (exit {})",
            s.code().unwrap_or(-1)
        ),
        Err(e) => eprintln!("warning: chcon not available: {e}"),
    }
}

/// Parse colon-separated paths from an environment variable.
#[cfg(target_os = "linux")]
fn env_paths(name: &str) -> Vec<PathBuf> {
    match std::env::var(name) {
        Ok(v) => arapuca::env::parse_paths(&v),
        Err(_) => Vec::new(),
    }
}

#[cfg(unix)]
use arapuca::wrapper::audit_layer;
/// Write an audit status line to the audit FD (if set).
///
/// Writes newline-delimited JSON. Errors are silently ignored — audit
/// is observability, not a security gate.
use arapuca::wrapper::which;
