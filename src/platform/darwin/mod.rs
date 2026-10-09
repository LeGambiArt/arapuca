//! macOS sandbox implementation using Apple's Seatbelt (`sandbox-exec`).
//!
//! Provides kernel-enforced filesystem and network restrictions on macOS.
//! Unlike Linux (Landlock + seccomp + cgroups), macOS uses a single
//! Seatbelt profile for filesystem/network policy and relies on rlimits
//! for resource limits (no cgroups).
//!
//! Memory enforcement is best-effort via polling (500ms interval) since
//! macOS has no cgroup-based OOM killer. A parent-PID watchdog replaces
//! Linux's `PR_SET_PDEATHSIG`.
//!
//! `sandbox-exec` is deprecated by Apple but still works on macOS 15.

mod darwin_profile;

use std::os::unix::io::{FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

use crate::audit::{
    AuditContext, AuditEvent, AuditVerbosity, InjectReason, InjectedEnvVar, SCHEMA_VERSION,
    SandboxLayer, SkipReason, sanitize_audit_string,
};
use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

/// macOS sandbox implementation.
pub struct Darwin;

impl Darwin {
    /// Create a new macOS sandbox.
    pub fn new() -> crate::Result<Self> {
        Ok(Darwin)
    }

    /// Find the arapuca wrapper binary.
    fn wrapper_path() -> Option<PathBuf> {
        crate::env::wrapper_path()
    }

    /// Resolve the uv cache path on macOS.
    fn uv_cache_path() -> Option<PathBuf> {
        // uv uses ~/Library/Caches/uv on macOS.
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Library/Caches/uv"))
    }

    /// Convert CPU percentage and max duration to RLIMIT_CPU seconds.
    ///
    /// The Go implementation uses: cpu_pct / 100 * duration_seconds.
    /// Example: 200% for 30 minutes = 2.0 * 1800 = 3600 seconds.
    fn cpu_pct_to_seconds(cpu_pct: u32, duration_minutes: u64) -> u64 {
        if cpu_pct == 0 || duration_minutes == 0 {
            return 0;
        }
        let factor = f64::from(cpu_pct) / 100.0;
        let duration_secs = duration_minutes * 60;
        (factor * duration_secs as f64) as u64
    }

    /// Start a memory monitoring thread that polls RSS and kills the
    /// process group if it exceeds the limit.
    ///
    /// This is a best-effort mechanism — the 500ms polling window means
    /// a process can briefly exceed the limit before being killed.
    fn start_memory_monitor(
        pid: u32,
        limit_mb: u64,
    ) -> Option<(
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        std::thread::JoinHandle<()>,
    )> {
        if limit_mb == 0 {
            return None;
        }
        let limit_kb = limit_mb * 1024;
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_clone = std::sync::Arc::clone(&cancel);
        let handle = std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(500));

                if cancel_clone.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }

                // Check if process still exists.
                let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
                if !alive {
                    break;
                }

                // Read RSS via ps.
                let output = Command::new("ps")
                    .args(["-o", "rss=", "-p", &pid.to_string()])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .output();

                let rss_kb = match output {
                    Ok(out) => {
                        let s = String::from_utf8_lossy(&out.stdout);
                        s.trim().parse::<u64>().unwrap_or(0)
                    }
                    Err(_) => continue,
                };

                if rss_kb > limit_kb {
                    log::warn!(
                        "memory limit exceeded: {rss_kb}KB > {limit_kb}KB, \
                         killing process group {pid}"
                    );
                    unsafe {
                        libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
                    }
                    break;
                }
            }
        });
        Some((cancel, handle))
    }

    /// Start a parent-PID watchdog thread.
    ///
    /// On macOS there is no `PR_SET_PDEATHSIG`. Instead, we poll
    /// `getppid()` every 2 seconds. If the parent PID changes (process
    /// was reparented to init/launchd), the subprocess is killed.
    fn start_parent_watchdog(child_pid: u32) {
        let original_ppid = unsafe { libc::getppid() } as u32;
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                // SAFETY: getppid() is a simple getter with no arguments.
                let current_ppid = unsafe { libc::getppid() } as u32;
                if current_ppid != original_ppid {
                    log::warn!(
                        "parent died (ppid changed {} -> {}), killing child {}",
                        original_ppid,
                        current_ppid,
                        child_pid
                    );
                    // SAFETY: Sending SIGKILL to the child's process group.
                    unsafe {
                        libc::kill(-(child_pid as libc::pid_t), libc::SIGKILL);
                    }
                    break;
                }
                // Also check if child is still alive.
                let alive = unsafe { libc::kill(child_pid as libc::pid_t, 0) } == 0;
                if !alive {
                    break;
                }
            }
        });
    }
}

impl Sandbox for Darwin {
    fn launch(&self, cfg: &Config, cmd: &str, args: &[&str]) -> crate::Result<Process> {
        cfg.profile.validate_unix_socket_policy()?;
        // Validate task ID and work directory.
        crate::sanitize_task_id(&cfg.task_id)?;
        crate::validate_work_dir(
            &cfg.work_dir,
            &cfg.profile.read_paths,
            &cfg.profile.write_paths,
        )?;

        let wrapper = Self::wrapper_path();
        let use_wrapper = wrapper.is_some();
        let proxy_mode = cfg.network_proxy_socket.is_some();
        let allow_network =
            cfg.profile.seccomp_profile == crate::SeccompProfile::Baseline && !proxy_mode;

        let audit_ctx = cfg
            .audit_sink
            .as_ref()
            .map(|sink| AuditContext::new(Arc::clone(sink), cfg.audit_verbosity.clone()));

        if let Some(ref ctx) = audit_ctx {
            let args_field = match ctx.verbosity() {
                AuditVerbosity::Verbose => {
                    Some(args.iter().map(|a| sanitize_audit_string(a)).collect())
                }
                _ => None,
            };
            ctx.emit(AuditEvent::SandboxInit {
                timestamp: ctx.timestamp(),
                wall_clock_epoch_ns: ctx.wall_clock_epoch_ns(),
                schema_version: SCHEMA_VERSION,
                task_id: sanitize_audit_string(&cfg.task_id),
                phase: sanitize_audit_string(&cfg.phase),
                command: sanitize_audit_string(cmd),
                arg_count: args.len(),
                args: args_field,
                principal: cfg.audit_principal.as_deref().map(sanitize_audit_string),
                correlation_id: cfg
                    .audit_correlation_id
                    .as_deref()
                    .map(sanitize_audit_string),
            })?;

            for layer in [
                SandboxLayer::Landlock,
                SandboxLayer::Seccomp,
                SandboxLayer::Cgroup,
                SandboxLayer::NetworkNamespace,
                SandboxLayer::NoNewPrivs,
                SandboxLayer::Pdeathsig,
                SandboxLayer::ProxyBridge,
            ] {
                ctx.emit(AuditEvent::LayerSkipped {
                    timestamp: ctx.timestamp(),
                    layer,
                    reason: SkipReason::PlatformUnsupported,
                })?;
            }

            let network_detail = if allow_network && cfg.profile.allow_network_listeners {
                "network=allowed,listeners=enabled"
            } else if allow_network {
                "network=allowed"
            } else if cfg.profile.allow_network_listeners {
                "network=listeners-enabled"
            } else if proxy_mode {
                "network=proxy-only"
            } else {
                "network=denied"
            };
            // Record Keychain access too: --allow-keychain widens the
            // sandbox (extra Mach services and Keychain file reads), so
            // it must leave an audit trail alongside the network mode.
            let keychain_detail = if cfg.profile.allow_keychain {
                "keychain=allowed"
            } else {
                "keychain=denied"
            };
            let seatbelt_detail = format!("{network_detail},{keychain_detail}");
            ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::Seatbelt,
                detail: Some(crate::audit::LayerDetail::Other(seatbelt_detail)),
            })?;
            ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::Setsid,
                detail: None,
            })?;
            ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::FdSanitization,
                detail: None,
            })?;
            if use_wrapper {
                ctx.emit(AuditEvent::LayerApplied {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::Rlimit,
                    detail: None,
                })?;
            }
        }

        // Create tmpdir and canonicalize for Seatbelt profile paths.
        // On macOS, /tmp -> /private/tmp. TmpDirGuard holds the canonical
        // path so that guard cleanup, Seatbelt profiles, and Process.tmp_dir
        // all use the same resolved path.
        let raw_tmp = crate::env::make_tmp_dir(&cfg.task_id)?;
        let canonical_tmp = std::fs::canonicalize(&raw_tmp).unwrap_or(raw_tmp);
        let tmp_guard = crate::env::TmpDirGuard::new(canonical_tmp);
        let tmp_dir = tmp_guard.path().to_path_buf();

        // Helper: canonicalize a path for Seatbelt profile embedding.
        // For files that don't exist yet (e.g. socket files),
        // canonicalize the parent directory and re-attach the filename.
        // This is critical on macOS where /tmp → /private/tmp and
        // /var → /private/var — Seatbelt matches kernel-resolved paths,
        // so profile paths must be canonical.
        let canon = |p: &std::path::Path| -> String {
            if let Ok(c) = std::fs::canonicalize(p) {
                return c.to_string_lossy().into_owned();
            }
            if let (Some(parent), Some(name)) = (p.parent(), p.file_name()) {
                if let Ok(cp) = std::fs::canonicalize(parent) {
                    return cp.join(name).to_string_lossy().into_owned();
                }
            }
            p.to_string_lossy().into_owned()
        };

        // Build profile data from config. All paths must be
        // canonicalized because Seatbelt resolves symlinks in access
        // paths but stores profile paths as-is.
        let mut read_paths: Vec<String> = cfg.profile.read_paths.iter().map(|p| canon(p)).collect();

        let mut write_paths: Vec<String> =
            cfg.profile.write_paths.iter().map(|p| canon(p)).collect();

        // Add socket dir to read paths so the agent can connect.
        let has_socket_dir = !cfg.socket_dir.as_os_str().is_empty();
        if has_socket_dir {
            read_paths.push(canon(&cfg.socket_dir));
        }

        // Add tmp_dir to write paths.
        write_paths.push(tmp_dir.to_string_lossy().into_owned());

        // Add uv cache to read paths if it exists.
        if let Some(uv_cache) = Self::uv_cache_path() {
            if uv_cache.exists() {
                read_paths.push(canon(&uv_cache));
            }
        }

        // Canonicalize cmd early so exec_paths and actual_cmd use
        // the same resolved path. Seatbelt does NOT resolve symlinks
        // in the target binary path for process-exec checks.
        let canonical_cmd = canon(std::path::Path::new(cmd));

        let mut exec_paths: Vec<String> = Vec::new();
        let cmd_canon_path = std::path::Path::new(&canonical_cmd);
        if let Some(parent) = cmd_canon_path.parent() {
            if !parent.as_os_str().is_empty() {
                exec_paths.push(parent.to_string_lossy().into_owned());
            }
        }
        // When allow_exec is set, read_paths should also be executable.
        // On Linux, Landlock applies LANDLOCK_ACCESS_FS_EXECUTE alongside
        // READ_FILE. On macOS, file-read* and process-exec are separate
        // Seatbelt operations, so we must explicitly add read_paths to
        // exec_paths. Without this, binaries found via PATH in read-only
        // directories (e.g. nvm's node inside a version prefix) cannot
        // be executed even though they are readable.
        if cfg.profile.allow_exec {
            for p in &read_paths {
                if !exec_paths.contains(p) {
                    exec_paths.push(p.clone());
                }
            }
        }

        // When Keychain access is requested, add the user's login
        // Keychain directory to read paths. The file-based login
        // keychain is read directly by Security.framework; the
        // securityd/trustd Mach services are granted by the profile.
        //
        // This runs after the allow_exec block on purpose: the
        // Keychains directory only holds `.keychain-db` files and must
        // never be granted process-exec, so it must not be copied into
        // exec_paths above.
        if cfg.profile.allow_keychain {
            if let Some(home) = std::env::var_os("HOME") {
                let kc = std::path::Path::new(&home).join("Library/Keychains");
                if kc.exists() {
                    read_paths.push(canon(&kc));
                }
            } else {
                log::warn!(
                    "--allow-keychain: HOME is unset, so the login Keychain \
                     directory cannot be located; Keychain reads will fail. \
                     Set HOME to the real home directory."
                );
            }
        }

        let control_socket = if has_socket_dir {
            Some(canon(&cfg.socket_dir.join("control.sock")))
        } else {
            None
        };
        let llm_socket = cfg.network_proxy_socket.as_ref().map(|p| canon(p));

        let profile_data = darwin_profile::ProfileData {
            read_paths,
            write_paths,
            exec_paths,
            control_socket,
            llm_socket,
            allow_network,
            allow_keychain: cfg.profile.allow_keychain,
            allow_network_listeners: cfg.profile.allow_network_listeners,
            tty: cfg.tty,
        };

        // Generate the Seatbelt profile.
        let profile_path = darwin_profile::generate_profile(&tmp_dir, &profile_data)?;

        // Build the command: sandbox-exec -f profile.sb -- cmd args...
        let mut actual_cmd = canonical_cmd;
        let mut actual_args: Vec<String> = args.iter().map(|a| a.to_string()).collect();

        // Wrap with sandbox-exec. Use the absolute path because the
        // arapuca wrapper binary calls execve(), which does NOT search
        // PATH. A bare "sandbox-exec" would fail with ENOENT.
        let sandbox_exec = which_sandbox_exec()
            .ok_or_else(|| Error::Process("sandbox-exec not found in PATH".into()))?;
        let sb_args = vec![
            "-f".to_string(),
            profile_path.to_string_lossy().into_owned(),
            "--".to_string(),
            actual_cmd,
        ];
        actual_cmd = sandbox_exec;
        let mut new_args = sb_args;
        new_args.extend(actual_args);
        actual_args = new_args;

        // Optionally wrap with arapuca binary for rlimits.
        // On macOS the wrapper only applies rlimits (Landlock/seccomp
        // are gated behind cfg(linux)).
        if let Some(ref wrapper_path) = wrapper {
            let mut wrapper_args = vec!["--".to_string(), actual_cmd];
            wrapper_args.extend(actual_args);
            actual_cmd = wrapper_path.to_string_lossy().into_owned();
            actual_args = wrapper_args;
        }

        let mut command = Command::new(&actual_cmd);
        command.args(&actual_args);

        // Set working directory.
        if let Some(ref work_dir) = cfg.work_dir {
            command.current_dir(work_dir);
        }

        // Build minimal environment with Homebrew PATH.
        let mut env_vars = crate::env::minimal_env(&tmp_dir);

        // Override PATH to include Homebrew.
        for entry in &mut env_vars {
            if entry.0 == "PATH" {
                entry.1 = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:\
                            /usr/local/sbin:/usr/sbin:/sbin"
                    .into();
            }
        }

        // When Keychain access is enabled, point HOME at the caller's real
        // home directory instead of the sandbox temp dir. The macOS
        // Keychain search list is derived from HOME; with the default temp
        // HOME the login keychain is absent from the search list and
        // Keychain items cannot be found (reads fail as "item not found").
        // Confinement is unaffected: access is bounded by the mount profile,
        // not by $HOME, so an un-mounted home still yields EPERM.
        if cfg.profile.allow_keychain {
            if let Some(home) = std::env::var_os("HOME") {
                let home = home.to_string_lossy().into_owned();
                if let Some(entry) = env_vars.iter_mut().find(|(k, _)| k == "HOME") {
                    entry.1 = home;
                } else {
                    env_vars.push(("HOME".into(), home));
                }
            }
        }

        // Add rlimit env vars for the wrapper (if using it).
        if wrapper.is_some() {
            let wrapper_env = crate::env::wrapper_env(&cfg.profile)?;
            env_vars.extend(wrapper_env);

            // Add RLIMIT_CPU if cpu_pct is set (convert % to seconds).
            // Use 30 minutes as default max duration.
            let cpu_seconds = Self::cpu_pct_to_seconds(cfg.profile.max_cpu_pct, 30);
            if cpu_seconds > 0 {
                env_vars.push(("ARAPUCA_RLIMIT_CPU".into(), cpu_seconds.to_string()));
            }
        }

        // Add network proxy socket (non-ARAPUCA prefix, not stripped).
        if let Some(ref proxy) = cfg.network_proxy_socket {
            env_vars.push((
                "AGENT_NETWORK_PROXY".into(),
                proxy.to_string_lossy().into_owned(),
            ));
        }

        // Append caller-supplied env vars (filtered for safety).
        let filter_result = crate::env::filter_caller_env(&cfg.env);
        env_vars.extend(filter_result.passed);

        // Forward HTTP(S) proxy vars from the launcher's own (trusted)
        // environment, bypassing the caller-env filter. Opt-in via
        // --allow-proxy-env for tools that must reach the network
        // through a local proxy in baseline network mode.
        //
        // Gate on allow_network so proxy vars (which may carry
        // credentials in the URL) are never injected when outbound
        // network is blocked by Seatbelt; otherwise the untrusted
        // process could read and exfiltrate them despite no egress.
        //
        // Injected keys are also recorded separately in the EnvPolicy
        // audit event so an auditor can tell launcher-injected vars apart
        // from caller-supplied vars that passed the filter.
        let mut injected_keys = Vec::new();
        if cfg.profile.allow_proxy_env && allow_network {
            for key in &[
                "HTTP_PROXY",
                "http_proxy",
                "HTTPS_PROXY",
                "https_proxy",
                "ALL_PROXY",
                "all_proxy",
                "NO_PROXY",
                "no_proxy",
            ] {
                if let Ok(val) = std::env::var(key) {
                    if !val.is_empty() {
                        env_vars.push(((*key).to_string(), val));
                        injected_keys.push(InjectedEnvVar {
                            key: (*key).to_string(),
                            reason: InjectReason::ProxyEnv,
                        });
                    }
                }
            }
        }

        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::EnvPolicy {
                timestamp: ctx.timestamp(),
                passed_keys: env_vars.iter().map(|(k, _)| k.clone()).collect(),
                injected_keys,
                dropped: filter_result.dropped,
            })?;
        }

        command.env_clear();
        for (k, v) in &env_vars {
            command.env(k, v);
        }

        // Validate extra FDs before PTY allocation so that validation
        // failures cannot leak openpty FDs.
        super::fd::validate_extra_fds(&cfg.extra_fds, cfg)?;
        let mut fds_to_inherit = std::mem::ManuallyDrop::new(cfg.extra_fds.clone());

        // ── PTY allocation (TTY mode) ─────────────────────────────
        let (pty_master_fd, pty_slave_fd) = if cfg.tty {
            if cfg.stdin.is_some() || cfg.stdout.is_some() || cfg.stderr.is_some() {
                return Err(Error::Validation(
                    "tty mode is incompatible with stdin/stdout/stderr redirection".into(),
                ));
            }

            let mut master: libc::c_int = -1;
            let mut slave: libc::c_int = -1;
            // SAFETY: openpty with null name/termios/winsize. No threads
            // are spawned yet (memory monitor and parent watchdog start
            // after spawn), so the CLOEXEC race window is safe.
            let ret = unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ret != 0 {
                return Err(Error::Process(format!(
                    "openpty: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: valid FDs from openpty.
            unsafe {
                libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC);
                libc::fcntl(slave, libc::F_SETFD, libc::FD_CLOEXEC);
            }

            // Copy parent's terminal size (fallback to 24x80).
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            // SAFETY: TIOCGWINSZ on stdin.
            if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } == 0
                && ws.ws_row > 0
                && ws.ws_col > 0
            {
                // SAFETY: TIOCSWINSZ on the PTY master.
                unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &ws) };
            } else {
                ws.ws_row = 24;
                ws.ws_col = 80;
                unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &ws) };
            }

            (Some(master), Some(slave))
        } else {
            (None, None)
        };

        // stdin/stdout/stderr redirection. In TTY mode, use Stdio::null()
        // to prevent the parent's real stdio from being inherited between
        // fork and pre_exec (where dup2 overwrites them with the PTY slave).
        if cfg.tty {
            command.stdin(Stdio::null());
            command.stdout(Stdio::null());
            command.stderr(Stdio::null());
        } else {
            crate::platform::setup_stdio(&mut command, cfg.stdin, "stdin", Command::stdin)?;
            crate::platform::setup_stdio(&mut command, cfg.stdout, "stdout", Command::stdout)?;
            crate::platform::setup_stdio(&mut command, cfg.stderr, "stderr", Command::stderr)?;
        }

        // Emit SandboxReady before spawn.
        if let Some(ref ctx) = audit_ctx {
            let mut applied = vec![
                SandboxLayer::Seatbelt,
                SandboxLayer::Setsid,
                SandboxLayer::EnvFilter,
                SandboxLayer::FdSanitization,
            ];
            if use_wrapper {
                applied.push(SandboxLayer::Rlimit);
            }
            if cfg.tty {
                ctx.emit(AuditEvent::LayerApplied {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::Pty,
                    detail: None,
                })?;
                applied.push(SandboxLayer::Pty);
            }
            ctx.emit(AuditEvent::SandboxReady {
                timestamp: ctx.timestamp(),
                applied_layers: applied,
                skipped_layers: vec![
                    SandboxLayer::Landlock,
                    SandboxLayer::Seccomp,
                    SandboxLayer::Cgroup,
                    SandboxLayer::NetworkNamespace,
                    SandboxLayer::NoNewPrivs,
                    SandboxLayer::Pdeathsig,
                    SandboxLayer::ProxyBridge,
                ],
            })?;
        }

        // SAFETY: pre_exec runs between fork and exec. Only async-signal-safe
        // functions are used (setsid, fcntl, dup2, close, ioctl).
        // ManuallyDrop prevents free() on the Vec in the child process.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }

                // Evacuate PTY slave FD above the remap ceiling if it
                // falls in [3, 3+N) — MUST happen before remap_fds.
                let mut slave_fd = pty_slave_fd;
                if let Some(ref mut sfd) = slave_fd {
                    let ceiling = 3 + fds_to_inherit.len() as i32;
                    if *sfd >= 3 && *sfd < ceiling {
                        let high = libc::fcntl(*sfd, libc::F_DUPFD_CLOEXEC, ceiling);
                        if high == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        libc::close(*sfd);
                        *sfd = high;
                    }
                }

                if !fds_to_inherit.is_empty() {
                    super::fd::remap_fds(&mut fds_to_inherit)?;
                }

                // PTY slave setup: acquire controlling terminal, then
                // redirect stdio. TIOCSCTTY runs after setsid() which
                // is the only valid ordering per POSIX.
                if let Some(sfd) = slave_fd {
                    // SAFETY: TIOCSCTTY on the slave PTY. arg=0: do not
                    // steal from another session. On macOS TIOCSCTTY is
                    // c_uint; the cast to c_ulong is a safe widening.
                    if libc::ioctl(sfd, libc::TIOCSCTTY as libc::c_ulong, 0i32) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(sfd, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(sfd, 1) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(sfd, 2) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if sfd > 2 {
                        libc::close(sfd);
                    }
                }

                Ok(())
            });
        }

        let pre_spawn_time = std::time::SystemTime::now();

        let child = command.spawn().map_err(|e| {
            if let Some(m) = pty_master_fd {
                // SAFETY: valid FD from openpty, cleanup on spawn failure.
                unsafe { libc::close(m) };
            }
            if let Some(s) = pty_slave_fd {
                // SAFETY: valid FD from openpty, cleanup on spawn failure.
                unsafe { libc::close(s) };
            }
            Error::Process(format!("start sandboxed process: {e}"))
        })?;

        // Close PTY slave in parent — only needed in the child.
        if let Some(s) = pty_slave_fd {
            // SAFETY: valid FD from openpty, no longer needed in parent.
            unsafe { libc::close(s) };
        }

        let pid = child.id();

        if let Some(ref ctx) = audit_ctx {
            if let Err(e) = ctx.emit(AuditEvent::ProcessStarted {
                timestamp: ctx.timestamp(),
                pid,
            }) {
                log::error!("audit emit failed: {e}");
            }
        }

        // Start memory monitor thread (best-effort RSS polling).
        let monitor = Self::start_memory_monitor(pid, cfg.profile.max_memory_mb);
        let (monitor_cancel, monitor_handle) = match monitor {
            Some((c, h)) => (Some(c), Some(h)),
            None => (None, None),
        };

        if let Some(ref ctx) = audit_ctx {
            let _ = ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::MemoryMonitor,
                detail: None,
            });
        }

        // Start parent-PID watchdog (replaces PR_SET_PDEATHSIG).
        Self::start_parent_watchdog(pid);

        if let Some(ref ctx) = audit_ctx {
            let _ = ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::ParentWatchdog,
                detail: None,
            });
        }

        let capture_denials = !allow_network && audit_ctx.is_some();

        Ok(Process {
            child: crate::process::ChildHandle::Managed(child),
            tmp_dir: tmp_guard.defuse(),
            waited: false,
            pty_master: pty_master_fd.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
            launch_timestamp: if capture_denials {
                Some(pre_spawn_time)
            } else {
                None
            },
            monitor_cancel,
            monitor_handle,
            audit_ctx,
            final_stats: None,
        })
    }

    fn available(&self) -> crate::Result<()> {
        // Check that sandbox-exec exists.
        Command::new("sandbox-exec")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| {
                Error::Process(format!(
                    "sandbox-exec not found: {e} \
                     (required for macOS sandbox)"
                ))
            })?;
        Ok(())
    }

    fn netns_available(&self) -> bool {
        false
    }

    fn cgroups_available(&self) -> bool {
        false
    }
}

/// Resolve the absolute path to `sandbox-exec`.
///
/// The arapuca wrapper binary uses `execve()` (not `execvp()`), which
/// requires an absolute path. A bare `"sandbox-exec"` would fail with
/// ENOENT because `execve()` does not search PATH.
fn which_sandbox_exec() -> Option<String> {
    // Fast path: standard location on macOS.
    if std::path::Path::new("/usr/bin/sandbox-exec").is_file() {
        return Some("/usr/bin/sandbox-exec".into());
    }
    // Fallback: search PATH.
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let candidate = std::path::Path::new(dir).join("sandbox-exec");
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_pct_to_seconds_basic() {
        // 200% for 30 min = 3600 seconds.
        assert_eq!(Darwin::cpu_pct_to_seconds(200, 30), 3600);
        // 100% for 30 min = 1800 seconds.
        assert_eq!(Darwin::cpu_pct_to_seconds(100, 30), 1800);
        // 0% = no limit.
        assert_eq!(Darwin::cpu_pct_to_seconds(0, 30), 0);
        // 0 duration = no limit.
        assert_eq!(Darwin::cpu_pct_to_seconds(200, 0), 0);
    }

    fn test_config_with_extra_fds(fds: Vec<i32>) -> crate::Config {
        crate::Config {
            profile: crate::Profile::default(),
            socket_dir: std::path::PathBuf::new(),
            task_id: "test".into(),
            phase: "test".into(),
            work_dir: None,
            stdin: None,
            stdout: None,
            stderr: None,
            extra_fds: fds,
            tty: false,
            network_proxy_socket: None,
            env: vec![],
            audit_sink: None,
            audit_verbosity: crate::audit::AuditVerbosity::default(),
            audit_principal: None,
            audit_correlation_id: None,
        }
    }

    #[test]
    fn darwin_extra_fds_rejects_stdin() {
        let cfg = test_config_with_extra_fds(vec![0]);
        let err = match Darwin.launch(&cfg, "/bin/true", &[]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for FD 0"),
        };
        assert!(err.contains("stdin/stdout/stderr"), "got: {err}");
    }

    #[test]
    fn darwin_extra_fds_rejects_duplicates() {
        let cfg = test_config_with_extra_fds(vec![5, 5]);
        let err = match Darwin.launch(&cfg, "/bin/true", &[]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for duplicate FDs"),
        };
        assert!(err.contains("duplicate FD"), "got: {err}");
    }

    #[test]
    fn darwin_extra_fds_rejects_too_many() {
        let fds: Vec<i32> = (3..20).collect();
        let cfg = test_config_with_extra_fds(fds);
        let err = match Darwin.launch(&cfg, "/bin/true", &[]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for too many FDs"),
        };
        assert!(err.contains("too many FDs"), "got: {err}");
    }

    #[test]
    fn darwin_tty_rejects_stdin_redirect() {
        let mut cfg = test_config_with_extra_fds(vec![]);
        cfg.tty = true;
        cfg.stdin = Some(5);
        let err = match Darwin.launch(&cfg, "/bin/true", &[]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for tty + stdin"),
        };
        assert!(err.contains("incompatible"), "got: {err}");
    }

    #[test]
    fn darwin_tty_rejects_stdout_redirect() {
        let mut cfg = test_config_with_extra_fds(vec![]);
        cfg.tty = true;
        cfg.stdout = Some(5);
        let err = match Darwin.launch(&cfg, "/bin/true", &[]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for tty + stdout"),
        };
        assert!(err.contains("incompatible"), "got: {err}");
    }

    #[test]
    fn darwin_tty_rejects_stderr_redirect() {
        let mut cfg = test_config_with_extra_fds(vec![]);
        cfg.tty = true;
        cfg.stderr = Some(5);
        let err = match Darwin.launch(&cfg, "/bin/true", &[]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for tty + stderr"),
        };
        assert!(err.contains("incompatible"), "got: {err}");
    }
}
