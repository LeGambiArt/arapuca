//! Linux sandbox implementation.
//!
//! Coordinates Landlock, seccomp, cgroups v2, and network namespace
//! isolation to launch fully sandboxed subprocesses.
//!
//! The subprocess is spawned with:
//! - CLONE_NEWNET (if UseNetNS) for network namespace isolation
//! - Setsid to detach from the host's session
//! - Minimal environment (HOME, TMPDIR, PATH, LANG only)
//! - Only explicitly listed FDs inherited (via extra_fds)
//! - All other FDs have CLOEXEC set by the Rust runtime
//!
//! Landlock, seccomp, and rlimits are applied by the arapuca wrapper
//! binary at startup (before exec-ing the agent).

use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

use crate::audit::{
    AuditContext, AuditEvent, AuditVerbosity, LayerDetail, SCHEMA_VERSION, SandboxLayer,
    SkipReason, sanitize_audit_string,
};
use crate::cgroup::{CgroupLimits, CgroupManager};
use crate::platform::Sandbox;
use crate::{CgroupPolicy, Config, Error, process::Process};

const CGROUP_DELEGATE_HINT: &str = "\
sudo mkdir -p /etc/systemd/system/user@.service.d && \
sudo sh -c 'printf \"[Service]\\nDelegate=cpu cpuset memory pids\\n\" \
> /etc/systemd/system/user@.service.d/delegate.conf' && \
sudo systemctl daemon-reload";

/// Linux sandbox implementation.
pub struct Linux {
    cgroup_mgr: Option<Arc<CgroupManager>>,
}

impl Linux {
    /// Create a new Linux sandbox, probing available features.
    pub fn new() -> crate::Result<Self> {
        let cgroup_mgr = CgroupManager::new()?.map(Arc::new);
        Ok(Self { cgroup_mgr })
    }

    /// Find the arapuca wrapper binary.
    fn wrapper_path() -> Option<PathBuf> {
        crate::env::wrapper_path()
    }
}

impl Sandbox for Linux {
    fn launch(&self, cfg: &Config, cmd: &str, args: &[&str]) -> crate::Result<Process> {
        cfg.profile.validate_unix_socket_policy()?;
        // Validate task ID.
        crate::sanitize_task_id(&cfg.task_id)?;

        // Defense-in-depth: reject /sys/fs/cgroup in sandbox paths.
        crate::reject_cgroup_paths(&cfg.profile.read_paths)?;
        crate::reject_cgroup_paths(&cfg.profile.write_paths)?;

        // Defense-in-depth: validate work_dir is within mounted paths.
        crate::validate_work_dir(
            &cfg.work_dir,
            &cfg.profile.read_paths,
            &cfg.profile.write_paths,
        )?;

        let tmp_guard = crate::env::TmpDirGuard::new(crate::env::make_tmp_dir(&cfg.task_id)?);

        let audit_ctx = cfg
            .audit_sink
            .as_ref()
            .map(|sink| AuditContext::new(Arc::clone(sink), cfg.audit_verbosity.clone()));

        // Track layers for SandboxReady summary.
        let mut applied_layers = Vec::new();
        let mut skipped_layers = Vec::new();

        // ── Emit SandboxInit ───────────────────────────────────────
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
        }

        // Determine the actual command. We may wrap it with the
        // arapuca binary (Landlock+seccomp) and/or unshare (netns).
        let mut actual_cmd = cmd.to_string();
        let mut actual_args: Vec<String> = args.iter().map(|a| a.to_string()).collect();

        // Layer 1: Landlock wrapper. If the arapuca binary is available
        // and filesystem paths are configured, wrap through it.
        let wrapper = Self::wrapper_path();
        let use_wrapper = wrapper.is_some();
        let pinned_wrapper =
            if cfg.profile.deny_unix_sockets && !crate::selfexec::selfexec_enabled() {
                let path = wrapper.as_ref().ok_or_else(|| {
                    Error::Validation("Unix socket denial requires a wrapper".into())
                })?;
                let pinned = super::wrapper_exec::PinnedWrapper::open(path)?;
                pinned.check()?;
                Some(pinned)
            } else {
                None
            };

        if use_wrapper {
            let wrapper_path = wrapper.as_ref().unwrap();
            let mut wrapper_args = vec!["--".to_string(), actual_cmd];
            wrapper_args.extend(actual_args);
            actual_cmd = pinned_wrapper
                .as_ref()
                .map(|p| p.path())
                .unwrap_or_else(|| wrapper_path.clone())
                .to_string_lossy()
                .into_owned();
            actual_args = wrapper_args;

            let abi = crate::landlock::abi_version();
            for layer in [
                SandboxLayer::Landlock,
                SandboxLayer::Rlimit,
                SandboxLayer::NoNewPrivs,
            ] {
                let detail = if layer == SandboxLayer::Landlock {
                    Some(LayerDetail::Landlock {
                        abi_version: abi,
                        fully_enforced: abi >= 5,
                    })
                } else {
                    None
                };
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerApplied {
                        timestamp: ctx.timestamp(),
                        layer: layer.clone(),
                        detail,
                    })?;
                }
                applied_layers.push(layer);
            }
            #[cfg(seccomp_supported)]
            {
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerApplied {
                        timestamp: ctx.timestamp(),
                        layer: SandboxLayer::Seccomp,
                        detail: None,
                    })?;
                }
                applied_layers.push(SandboxLayer::Seccomp);
            }
            #[cfg(not(seccomp_supported))]
            {
                log::warn!("seccomp not available on this architecture");
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerSkipped {
                        timestamp: ctx.timestamp(),
                        layer: SandboxLayer::Seccomp,
                        reason: SkipReason::PlatformUnsupported,
                    })?;
                }
                skipped_layers.push(SandboxLayer::Seccomp);
            }
        } else {
            // Wrapper binary not available — no
            // Landlock/seccomp/rlimit/NO_NEW_PRIVS.
            //
            // On seccomp-supported architectures (x86_64, aarch64),
            // always fail: the sandbox is meaningless without the
            // wrapper applying Landlock + seccomp + rlimits.
            // On other architectures, only fail if filesystem
            // restrictions were explicitly requested.
            if cfg!(seccomp_supported) {
                return Err(Error::Process(
                    "arapuca wrapper binary not found — refusing to launch \
                     without Landlock/seccomp enforcement"
                        .into(),
                ));
            }
            let has_paths =
                !cfg.profile.read_paths.is_empty() || !cfg.profile.write_paths.is_empty();
            if has_paths {
                return Err(Error::Process(
                    "filesystem restrictions requested but arapuca wrapper binary \
                     not found"
                        .into(),
                ));
            }
            let reason = SkipReason::NotAvailable;
            for layer in [
                SandboxLayer::Landlock,
                SandboxLayer::Rlimit,
                SandboxLayer::NoNewPrivs,
            ] {
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerSkipped {
                        timestamp: ctx.timestamp(),
                        layer: layer.clone(),
                        reason: reason.clone(),
                    })?;
                }
                skipped_layers.push(layer);
            }
            #[cfg(seccomp_supported)]
            {
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerSkipped {
                        timestamp: ctx.timestamp(),
                        layer: SandboxLayer::Seccomp,
                        reason: reason.clone(),
                    })?;
                }
                skipped_layers.push(SandboxLayer::Seccomp);
            }
            #[cfg(not(seccomp_supported))]
            {
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerSkipped {
                        timestamp: ctx.timestamp(),
                        layer: SandboxLayer::Seccomp,
                        reason: SkipReason::PlatformUnsupported,
                    })?;
                }
                skipped_layers.push(SandboxLayer::Seccomp);
            }
        }

        // ── CONNECT proxy (allowed_hosts) ──────────────────────────
        // If the caller supplied allowed_hosts, fork the CONNECT proxy
        // now (before any netns decisions), then use the proxy socket
        // as the effective network_proxy_socket.
        //
        // The guard ensures cleanup (kill child, remove socket dir) if
        // any subsequent operation in launch() fails before the proxy
        // state is moved into Process.
        struct ConnectProxyGuard {
            pid: Option<i32>,
            pidfd: Option<i32>,
            socket: Option<std::path::PathBuf>,
        }
        impl ConnectProxyGuard {
            fn defuse(&mut self) {
                self.pid = None;
                self.pidfd = None;
                self.socket = None;
            }
        }
        impl Drop for ConnectProxyGuard {
            fn drop(&mut self) {
                crate::bridge::cleanup_connect_proxy(self.pid, self.pidfd, &self.socket);
            }
        }

        let mut connect_proxy_guard = if !cfg.allowed_hosts.is_empty() {
            let (sock, pid, pidfd) =
                crate::bridge::fork_connect_proxy(&cfg.allowed_hosts, cfg.profile.seccomp_debug)?;
            ConnectProxyGuard {
                pid: Some(pid),
                pidfd: Some(pidfd),
                socket: Some(sock),
            }
        } else {
            ConnectProxyGuard {
                pid: None,
                pidfd: None,
                socket: None,
            }
        };

        let connect_proxy_pid_local = connect_proxy_guard.pid;
        let connect_proxy_pidfd_local = connect_proxy_guard.pidfd;
        let connect_proxy_socket_local = connect_proxy_guard.socket.clone();

        // Effective proxy socket: prefer the newly forked proxy; fall
        // back to the caller-supplied `network_proxy_socket`.
        let effective_proxy_socket: Option<&std::path::Path> = connect_proxy_socket_local
            .as_deref()
            .or(cfg.network_proxy_socket.as_deref());

        // When allowed_hosts is set, network namespace isolation is
        // implicitly enabled (the proxy only makes sense inside netns).
        let effective_use_netns = cfg.profile.use_netns || connect_proxy_socket_local.is_some();

        // ── DNS capture eligibility ────────────────────────────────
        let mount_ns_ok =
            cfg.profile.dns_capture && effective_use_netns && crate::netns::mount_ns_available();
        let dns_capture_active = mount_ns_ok;

        if cfg.profile.dns_capture && !dns_capture_active {
            if !effective_use_netns {
                log::warn!("DNS capture requires use_netns");
            } else if !mount_ns_ok {
                log::warn!(
                    "DNS capture requires mount namespace support (unshare --mount); \
                     falling back to netns-only"
                );
            }
        }

        // ── Network namespace ──────────────────────────────────────
        let mut command = if effective_use_netns {
            let mut c = Command::new("unshare");
            if dns_capture_active && use_wrapper {
                c.args(["--user", "--net", "--mount", "--map-root-user", "--"]);
            } else {
                c.args(["--user", "--net", "--map-root-user", "--"]);
            }
            c.arg(&actual_cmd);
            c.args(&actual_args);
            if let Some(ref ctx) = audit_ctx {
                ctx.emit(AuditEvent::LayerApplied {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::NetworkNamespace,
                    detail: None,
                })?;
            }
            applied_layers.push(SandboxLayer::NetworkNamespace);
            c
        } else if cfg.profile.use_pidns {
            // PID namespace without network namespace: need a user
            // namespace for unprivileged unshare(CLONE_NEWPID).
            let mut c = Command::new("unshare");
            c.args(["--user", "--map-root-user", "--"]);
            c.arg(&actual_cmd);
            c.args(&actual_args);
            if let Some(ref ctx) = audit_ctx {
                ctx.emit(AuditEvent::LayerSkipped {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::NetworkNamespace,
                    reason: SkipReason::NotConfigured,
                })?;
            }
            skipped_layers.push(SandboxLayer::NetworkNamespace);
            c
        } else {
            let mut c = Command::new(&actual_cmd);
            c.args(&actual_args);
            if let Some(ref ctx) = audit_ctx {
                ctx.emit(AuditEvent::LayerSkipped {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::NetworkNamespace,
                    reason: SkipReason::NotConfigured,
                })?;
            }
            skipped_layers.push(SandboxLayer::NetworkNamespace);
            c
        };

        // Set working directory.
        if let Some(ref work_dir) = cfg.work_dir {
            command.current_dir(work_dir);
        }

        // Build minimal environment.
        let mut env_vars = crate::env::minimal_env(tmp_guard.path());

        // Add Landlock/rlimit env vars for the wrapper.
        if use_wrapper {
            let mut profile = cfg.profile.clone();
            profile.write_paths.push(tmp_guard.path().to_path_buf());
            profile.read_paths.push(tmp_guard.path().to_path_buf());
            env_vars.extend(crate::env::wrapper_env(&profile)?);
        }

        // Add network proxy socket (non-ARAPUCA prefix, not stripped).
        if let Some(proxy) = effective_proxy_socket {
            env_vars.push((
                "AGENT_NETWORK_PROXY".into(),
                proxy.to_string_lossy().into_owned(),
            ));
        }

        // If allowed_hosts caused a connect proxy to be forked, emit
        // an audit event for the ConnectProxy layer now that we have
        // the effective socket path.
        if connect_proxy_socket_local.is_some() {
            if let Some(ref ctx) = audit_ctx {
                ctx.emit(AuditEvent::LayerApplied {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::ConnectProxy,
                    detail: None,
                })?;
            }
            applied_layers.push(SandboxLayer::ConnectProxy);
        }

        // Configure the proxy bridge when netns + proxy socket are
        // both set. The wrapper binary forks a TCP-to-UDS relay child.
        // The library only configures the env var here — the actual
        // bridge fork and readiness confirmation happen inside the
        // wrapper binary. The binary emits its own audit event on
        // successful bridge startup.
        match crate::env::bridge_env(effective_use_netns, effective_proxy_socket) {
            Ok(Some(kv)) => {
                env_vars.push(kv);
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerApplied {
                        timestamp: ctx.timestamp(),
                        layer: SandboxLayer::ProxyBridge,
                        detail: Some(LayerDetail::ProxyBridge {
                            port: crate::env::BRIDGE_PORT,
                            uds_path: effective_proxy_socket
                                .map(|p| p.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                        }),
                    })?;
                }
                applied_layers.push(SandboxLayer::ProxyBridge);
            }
            Ok(None) => {
                if let Some(ref ctx) = audit_ctx {
                    ctx.emit(AuditEvent::LayerSkipped {
                        timestamp: ctx.timestamp(),
                        layer: SandboxLayer::ProxyBridge,
                        reason: SkipReason::NotConfigured,
                    })?;
                }
                skipped_layers.push(SandboxLayer::ProxyBridge);
            }
            Err(e) => {
                return Err(e);
            }
        }

        // Append caller-supplied env vars (filtered for safety).
        let filter_result = crate::env::filter_caller_env(&cfg.env);
        env_vars.extend(filter_result.passed);

        // ── Emit EnvPolicy ─────────────────────────────────────────
        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::EnvPolicy {
                timestamp: ctx.timestamp(),
                passed_keys: env_vars.iter().map(|(k, _)| k.clone()).collect(),
                injected_keys: Vec::new(),
                dropped: filter_result.dropped,
            })?;
        }
        applied_layers.push(SandboxLayer::EnvFilter);

        command.env_clear();
        for (k, v) in &env_vars {
            command.env(k, v);
        }
        let wrapper_exec_fd = pinned_wrapper.as_ref().map(|p| p.fd());
        if let Some(fd) = wrapper_exec_fd {
            command.env("ARAPUCA_WRAPPER_EXEC_FD", fd.to_string());
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
            // SAFETY: openpty with null name/termios/winsize. Parent is
            // single-threaded at this point (no threads spawned yet), so
            // the CLOEXEC race window is safe.
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
            if unsafe { libc::ioctl(0, libc::TIOCGWINSZ as libc::Ioctl, &mut ws) } == 0
                && ws.ws_row > 0
                && ws.ws_col > 0
            {
                // SAFETY: TIOCSWINSZ on the PTY master.
                unsafe { libc::ioctl(master, libc::TIOCSWINSZ as libc::Ioctl, &ws) };
            } else {
                ws.ws_row = 24;
                ws.ws_col = 80;
                unsafe { libc::ioctl(master, libc::TIOCSWINSZ as libc::Ioctl, &ws) };
            }

            (Some(master), Some(slave))
        } else {
            (None, None)
        };

        // Set stdin/stdout/stderr redirection.
        if cfg.tty {
            command.stdin(Stdio::null());
            command.stdout(Stdio::null());
            command.stderr(Stdio::null());
        } else {
            super::setup_stdio(&mut command, cfg.stdin, "stdin", Command::stdin)?;
            super::setup_stdio(&mut command, cfg.stdout, "stdout", Command::stdout)?;
            super::setup_stdio(&mut command, cfg.stderr, "stderr", Command::stderr)?;
        }

        // ── Audit pipe for wrapper binary verification ─────────────
        // When auditing is active and the wrapper binary is used, create
        // a pipe so the wrapper can report which layers it actually
        // applied. The write end is passed as an extra FD; the parent
        // reads from the read end after spawn.
        //
        // Pipe FDs are tracked in pipe_guard so early returns (? on
        // emit calls between pipe creation and spawn) close them
        // automatically via Drop. Defused after spawn succeeds.
        struct PipeGuard(Vec<RawFd>);
        impl PipeGuard {
            fn push(&mut self, fd: RawFd) {
                self.0.push(fd);
            }
            fn defuse(mut self) {
                self.0.clear();
            }
        }
        impl Drop for PipeGuard {
            fn drop(&mut self) {
                for &fd in &self.0 {
                    unsafe { libc::close(fd) };
                }
            }
        }
        let mut pipe_guard = PipeGuard(Vec::new());

        let audit_pipe = if audit_ctx.is_some() && use_wrapper {
            let mut fds = [0i32; 2];
            // SAFETY: fds is a valid 2-element array. O_CLOEXEC prevents
            // leaking the read end to the child process.
            let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
            if ret == 0 {
                let target_fd = 3 + fds_to_inherit.len() as i32;
                // Bypasses validate_extra_fds intentionally: pipe2 returns
                // the lowest unused FDs, so the write-end cannot collide
                // with any already-open user FD in fds_to_inherit.
                fds_to_inherit.push(fds[1]);
                pipe_guard.push(fds[0]);
                pipe_guard.push(fds[1]);
                Some((fds[0], fds[1], target_fd))
            } else {
                log::warn!("audit pipe creation failed, continuing without");
                None
            }
        } else {
            None
        };

        // Add ARAPUCA_AUDIT_FD to wrapper env so it knows which FD to write to.
        if let Some((_, _, target_fd)) = audit_pipe {
            command.env("ARAPUCA_AUDIT_FD", target_fd.to_string());
        }

        // ── DNS audit pipe ────────────────────────────────────────
        // When DNS capture is enabled, create a pipe for the bridge's
        // DNS server to write NDJSON audit lines. The parent reads
        // these after the process exits and emits NetworkBlocked events.
        let dns_audit_pipe = if dns_capture_active && use_wrapper {
            let mut fds = [0i32; 2];
            let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
            if ret == 0 {
                let target_fd = 3 + fds_to_inherit.len() as i32;
                fds_to_inherit.push(fds[1]);
                command.env("ARAPUCA_DNS_AUDIT_FD", target_fd.to_string());
                pipe_guard.push(fds[0]);
                pipe_guard.push(fds[1]);
                Some((fds[0], fds[1]))
            } else {
                log::warn!("DNS audit pipe creation failed, continuing without");
                None
            }
        } else {
            None
        };

        if let Some(ref ctx) = audit_ctx {
            if dns_audit_pipe.is_some() {
                ctx.emit(AuditEvent::LayerApplied {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::DnsCapture,
                    detail: Some(LayerDetail::DnsCapture { port: 53 }),
                })?;
                applied_layers.push(SandboxLayer::DnsCapture);
            } else {
                let reason = if !cfg.profile.dns_capture {
                    SkipReason::NotConfigured
                } else if !cfg!(feature = "serde") {
                    SkipReason::ComponentMissing(
                        "serde feature required for DNS audit parsing".into(),
                    )
                } else if !use_wrapper {
                    SkipReason::ComponentMissing("wrapper binary not available".into())
                } else {
                    SkipReason::PartialFailure("mount namespace unavailable".into())
                };
                ctx.emit(AuditEvent::LayerSkipped {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::DnsCapture,
                    reason,
                })?;
                skipped_layers.push(SandboxLayer::DnsCapture);
            }
        }

        // ── Unotify audit pipe ─────────────────────────────────────
        // When file access or network auditing is enabled, create a
        // pipe for the unotify supervisor to write NDJSON audit lines.
        let unotify_wants = (cfg.profile.audit_file_access || cfg.profile.audit_network)
            && use_wrapper
            && cfg!(feature = "serde");
        let unotify_audit_pipe = if unotify_wants {
            let mut fds = [0i32; 2];
            let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
            if ret == 0 {
                let target_fd = 3 + fds_to_inherit.len() as i32;
                fds_to_inherit.push(fds[1]);
                command.env("ARAPUCA_UNOTIFY_AUDIT_FD", target_fd.to_string());
                pipe_guard.push(fds[0]);
                pipe_guard.push(fds[1]);
                // Also set the config env var.
                if let Some(kv) = crate::env::unotify_env(&cfg.profile) {
                    command.env(&kv.0, &kv.1);
                }
                Some((fds[0], fds[1]))
            } else {
                log::warn!("unotify audit pipe creation failed, continuing without");
                None
            }
        } else {
            None
        };

        if let Some(ref ctx) = audit_ctx {
            if unotify_audit_pipe.is_some() {
                ctx.emit(AuditEvent::LayerApplied {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::UnotifySupervisor,
                    detail: None,
                })?;
                applied_layers.push(SandboxLayer::UnotifySupervisor);
            } else {
                let reason = if !cfg.profile.audit_file_access && !cfg.profile.audit_network {
                    SkipReason::NotConfigured
                } else if !cfg!(feature = "serde") {
                    SkipReason::ComponentMissing(
                        "serde feature required for unotify audit parsing".into(),
                    )
                } else if !use_wrapper {
                    SkipReason::ComponentMissing("wrapper binary not available".into())
                } else {
                    SkipReason::PartialFailure("pipe creation failed".into())
                };
                ctx.emit(AuditEvent::LayerSkipped {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::UnotifySupervisor,
                    reason,
                })?;
                skipped_layers.push(SandboxLayer::UnotifySupervisor);
            }
        }

        // ── PID namespace pipe ─────────────────────────────────────
        // When PID namespace is active, create a pipe for the wrapper
        // parent to report the target's host PID. Set ARAPUCA_PID_NS
        // so the wrapper knows to call unshare(CLONE_NEWPID) + fork().
        let pid_report_pipe = if cfg.profile.use_pidns && use_wrapper {
            command.env("ARAPUCA_PID_NS", "1");
            let mut fds = [0i32; 2];
            let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
            if ret == 0 {
                let target_fd = 3 + fds_to_inherit.len() as i32;
                fds_to_inherit.push(fds[1]);
                command.env("ARAPUCA_PID_REPORT_FD", target_fd.to_string());
                pipe_guard.push(fds[0]);
                pipe_guard.push(fds[1]);
                Some((fds[0], fds[1]))
            } else {
                log::warn!("PID report pipe creation failed, continuing without pidns");
                None
            }
        } else {
            None
        };

        // ── Create cgroup ──────────────────────────────────────────
        let limits = CgroupLimits {
            memory_max_mb: cfg.profile.max_memory_mb,
            pids_max: cfg.profile.max_pids,
            cpu_max_pct: cfg.profile.max_cpu_pct,
            pids_overhead: (if cfg.profile.use_pidns { 1 } else { 0 })
                + (if effective_use_netns { 1 } else { 0 }),
        };

        let mut cgroup_path = None;
        if let Some(ref mgr) = self.cgroup_mgr {
            if limits.has_limits() {
                match mgr.create(&cfg.task_id, &limits) {
                    Ok(result) => {
                        if !result.degraded.is_empty() {
                            match cfg.profile.cgroup_policy {
                                CgroupPolicy::Required => {
                                    if let Some(ref p) = result.path {
                                        let _ = mgr.destroy(p);
                                    }
                                    return Err(Error::Cgroup(format!(
                                        "resource limits requested but controllers \
                                         not delegated: {} — fix with: {CGROUP_DELEGATE_HINT}",
                                        result.degraded.join(", ")
                                    )));
                                }
                                CgroupPolicy::BestEffort => {
                                    let msg = if result.path.is_some() {
                                        "enforcement is partial"
                                    } else {
                                        "no controllers available — enforcement is not active"
                                    };
                                    log::warn!(
                                        "cgroup: controllers not delegated: {} — {msg}",
                                        result.degraded.join(", ")
                                    );
                                }
                            }
                        }
                        if let Some(p) = result.path {
                            if !result.swap_disabled {
                                log::warn!("cgroup: memory.swap.max could not be set");
                            }
                            if let Some(ref ctx) = audit_ctx {
                                ctx.emit(AuditEvent::LayerApplied {
                                    timestamp: ctx.timestamp(),
                                    layer: SandboxLayer::Cgroup,
                                    detail: Some(LayerDetail::Cgroup {
                                        path: sanitize_audit_string(&p.to_string_lossy()),
                                        swap_disabled: result.swap_disabled,
                                        degraded: result.degraded.clone(),
                                    }),
                                })?;
                            }
                            applied_layers.push(SandboxLayer::Cgroup);
                            cgroup_path = Some(p);
                        } else {
                            if let Some(ref ctx) = audit_ctx {
                                ctx.emit(AuditEvent::LayerSkipped {
                                    timestamp: ctx.timestamp(),
                                    layer: SandboxLayer::Cgroup,
                                    reason: SkipReason::NotAvailable,
                                })?;
                            }
                            skipped_layers.push(SandboxLayer::Cgroup);
                        }
                    }
                    Err(e) => {
                        return Err(Error::Cgroup(format!("cgroup creation failed: {e}")));
                    }
                }
            }
        } else if limits.has_limits() {
            match cfg.profile.cgroup_policy {
                CgroupPolicy::Required => {
                    return Err(Error::Cgroup(format!(
                        "resource limits requested (memory={}MB, cpu={}%, pids={}) \
                         but cgroups unavailable — fix with: {CGROUP_DELEGATE_HINT}",
                        cfg.profile.max_memory_mb, cfg.profile.max_cpu_pct, cfg.profile.max_pids
                    )));
                }
                CgroupPolicy::BestEffort => {
                    log::warn!(
                        "cgroup: resource limits requested (memory={}MB, cpu={}%, pids={}) \
                         but cgroups unavailable — limits will not be enforced",
                        cfg.profile.max_memory_mb,
                        cfg.profile.max_cpu_pct,
                        cfg.profile.max_pids
                    );
                    if let Some(ref ctx) = audit_ctx {
                        ctx.emit(AuditEvent::LayerSkipped {
                            timestamp: ctx.timestamp(),
                            layer: SandboxLayer::Cgroup,
                            reason: SkipReason::NotAvailable,
                        })?;
                    }
                    skipped_layers.push(SandboxLayer::Cgroup);
                }
            }
        }

        // ── Cgroup sync pipe ──────────────────────────────────────
        // When a cgroup was successfully created, create a parent→child
        // pipe so the wrapper blocks until the parent has added the PID
        // to the cgroup. This closes the race window where the child
        // runs without cgroup limits between spawn and add_pid.
        let cgroup_sync_pipe = if cgroup_path.is_some() {
            let mut fds = [0i32; 2];
            // Both ends created with O_CLOEXEC to avoid leaking the
            // write end if another thread forks between pipe2 and
            // fcntl. The read end's CLOEXEC is cleared by remap_fds
            // when it's placed in the fds_to_inherit array.
            let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
            if ret == 0 {
                let target_fd = 3 + fds_to_inherit.len() as i32;
                fds_to_inherit.push(fds[0]);
                command.env("ARAPUCA_CGROUP_SYNC_FD", target_fd.to_string());
                pipe_guard.push(fds[0]);
                pipe_guard.push(fds[1]);
                Some((fds[0], fds[1]))
            } else {
                log::warn!("cgroup sync pipe creation failed, continuing without");
                None
            }
        } else {
            None
        };

        // ── Emit pre_exec layer events from parent ─────────────────
        // pre_exec is async-signal-safe — no AuditContext allowed inside.
        // We emit from the parent with the semantic "will be applied."
        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::Setsid,
                detail: None,
            })?;
            ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::Pdeathsig,
                detail: None,
            })?;

            let inherited: Vec<i32> = (0..fds_to_inherit.len()).map(|i| (3 + i) as i32).collect();
            ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::FdSanitization,
                detail: None,
            })?;
            ctx.emit(AuditEvent::FdInheritance {
                timestamp: ctx.timestamp(),
                inherited_fds: inherited,
                stdin_redirected: cfg.stdin.is_some() || cfg.tty,
                stdout_redirected: cfg.stdout.is_some() || cfg.tty,
                stderr_redirected: cfg.stderr.is_some() || cfg.tty,
            })?;
        }
        applied_layers.push(SandboxLayer::Setsid);
        applied_layers.push(SandboxLayer::Pdeathsig);
        applied_layers.push(SandboxLayer::FdSanitization);

        if let Some(ref ctx) = audit_ctx {
            if cfg.profile.use_pidns && pid_report_pipe.is_some() {
                ctx.emit(AuditEvent::LayerApplied {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::PidNamespace,
                    detail: None,
                })?;
                applied_layers.push(SandboxLayer::PidNamespace);
            } else {
                let reason = if !cfg.profile.use_pidns {
                    SkipReason::NotConfigured
                } else {
                    SkipReason::PartialFailure("PID report pipe creation failed".into())
                };
                ctx.emit(AuditEvent::LayerSkipped {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::PidNamespace,
                    reason,
                })?;
                skipped_layers.push(SandboxLayer::PidNamespace);
            }
        }

        #[cfg(unix)]
        if cfg.tty {
            if let Some(ref ctx) = audit_ctx {
                ctx.emit(AuditEvent::LayerApplied {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::Pty,
                    detail: None,
                })?;
            }
            applied_layers.push(SandboxLayer::Pty);
        }

        // SAFETY: pre_exec runs between fork and exec. Only
        // async-signal-safe functions are permitted. We use raw libc
        // calls (setsid, prctl) and fd::remap_fds (fcntl, dup2, close).
        // ManuallyDrop prevents free() on the Vec in the child process.
        let parent_pid = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    libc::_exit(1);
                }
                if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // Evacuate PTY slave FD above the remap ceiling if it
                // falls in [3, 3+N) — MUST happen before remap_fds.
                #[cfg(unix)]
                let mut slave_fd = pty_slave_fd;
                #[cfg(unix)]
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
                if let Some(fd) = wrapper_exec_fd {
                    super::wrapper_exec::inherit_exec_fd(fd)?;
                }

                // PTY slave setup: acquire controlling terminal, then
                // redirect stdio. TIOCSCTTY runs after setsid() which
                // is the only valid ordering per POSIX.
                #[cfg(unix)]
                if let Some(sfd) = slave_fd {
                    // SAFETY: TIOCSCTTY on the slave PTY. arg=0: do not
                    // steal from another session (the slave is always
                    // unowned after openpty + setsid).
                    if libc::ioctl(sfd, libc::TIOCSCTTY as libc::Ioctl, 0i32) != 0 {
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

        // ── Emit policy summary events ─────────────────────────────
        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::FilesystemPolicy {
                timestamp: ctx.timestamp(),
                read_paths: cfg
                    .profile
                    .read_paths
                    .iter()
                    .map(|p| sanitize_audit_string(&p.to_string_lossy()))
                    .collect(),
                write_paths: cfg
                    .profile
                    .write_paths
                    .iter()
                    .map(|p| sanitize_audit_string(&p.to_string_lossy()))
                    .collect(),
            })?;

            ctx.emit(AuditEvent::ResourceLimits {
                timestamp: ctx.timestamp(),
                memory_mb: cfg.profile.max_memory_mb,
                cpu_pct: cfg.profile.max_cpu_pct,
                max_pids: cfg.profile.max_pids,
                cpu_timeout_secs: cfg.profile.cpu_timeout_secs,
                max_file_size_mb: cfg.profile.max_file_size_mb,
                max_open_files: cfg.profile.max_open_files,
                allow_exec: cfg.profile.allow_exec,
            })?;

            ctx.emit(AuditEvent::NetworkPolicy {
                timestamp: ctx.timestamp(),
                isolated: effective_use_netns,
                proxy_socket: effective_proxy_socket
                    .map(|p| sanitize_audit_string(&p.to_string_lossy())),
            })?;

            #[cfg(seccomp_supported)]
            {
                let seccomp = crate::seccomp::summary(
                    &cfg.profile.seccomp_profile,
                    cfg.profile.deny_unix_sockets,
                );
                ctx.emit(AuditEvent::SeccompPolicy {
                    timestamp: ctx.timestamp(),
                    tier1_kill_count: seccomp.tier1_kill_count,
                    tier2_eperm_count: seccomp.tier2_eperm_count,
                    socket_filter: seccomp.socket_filter,
                    deny_unix_sockets: seccomp.deny_unix_sockets,
                    prctl_filter: seccomp.prctl_filter,
                    clone_ns_filter: seccomp.clone_ns_filter,
                    clone3_enosys: seccomp.clone3_enosys,
                    io_uring_enosys: seccomp.io_uring_enosys,
                    execveat_filter: seccomp.execveat_filter,
                    kill_filter: seccomp.kill_filter,
                    allow_exec: cfg.profile.allow_exec,
                })?;
            }
        }

        // ── Emit SandboxReady ──────────────────────────────────────
        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::SandboxReady {
                timestamp: ctx.timestamp(),
                applied_layers: applied_layers.clone(),
                skipped_layers: skipped_layers.clone(),
            })?;
        }

        // ── Spawn ──────────────────────────────────────────────────
        // Defuse the pipe guard — from here on, pipes are closed
        // explicitly (error handler on spawn failure, or post-spawn
        // cleanup on success).
        pipe_guard.defuse();

        let mut child = command.spawn().map_err(|e| {
            if let Some(ref ctx) = audit_ctx {
                let _ = ctx.emit(AuditEvent::LayerFailed {
                    timestamp: ctx.timestamp(),
                    layer: SandboxLayer::ProcessSpawn,
                    error: sanitize_audit_string(&format!("spawn failed: {e}")),
                });
            }
            if let Some((read_fd, write_fd, _)) = audit_pipe {
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
            }
            if let Some((read_fd, write_fd)) = dns_audit_pipe {
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
            }
            if let Some((read_fd, write_fd)) = unotify_audit_pipe {
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
            }
            if let Some((read_fd, write_fd)) = pid_report_pipe {
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
            }
            if let Some((read_fd, write_fd)) = cgroup_sync_pipe {
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
            }
            #[cfg(unix)]
            {
                if let Some(m) = pty_master_fd {
                    unsafe { libc::close(m) };
                }
                if let Some(s) = pty_slave_fd {
                    unsafe { libc::close(s) };
                }
            }
            if let Some(ref path) = cgroup_path {
                if let Some(ref mgr) = self.cgroup_mgr {
                    let _ = mgr.destroy(path);
                }
            }
            Error::Process(format!("start sandboxed process: {e}"))
        })?;

        // ── Open pidfd for race-free signaling ────────────────────
        let mut pidfd: Option<std::os::unix::io::OwnedFd> = {
            let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as i32, 0) };
            if ret >= 0 {
                Some(unsafe { std::os::unix::io::OwnedFd::from_raw_fd(ret as i32) })
            } else {
                log::warn!(
                    "pidfd_open failed: {} (falling back to kill)",
                    std::io::Error::last_os_error()
                );
                None
            }
        };
        let mut stored_target_pid: Option<u32> = None;

        // ── Close PTY slave in parent ──────────────────────────────
        #[cfg(unix)]
        if let Some(s) = pty_slave_fd {
            // SAFETY: valid FD from openpty, no longer needed in parent.
            unsafe { libc::close(s) };
        }

        // ── Close sync pipe read end in parent ────────────────────
        if let Some((read_fd, _)) = cgroup_sync_pipe {
            unsafe { libc::close(read_fd) };
        }

        // ── Add PID to cgroup BEFORE reading audit pipe ───────────
        // The wrapper blocks on the sync pipe at startup, waiting for
        // the parent to confirm cgroup membership. We must do add_pid
        // + sync_write before the audit pipe read, otherwise the
        // parent would deadlock (waiting for audit EOF while the
        // wrapper waits for the sync byte).
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &cgroup_path) {
            if let Err(e) = mgr.add_pid(path, child.id()) {
                // Close sync pipe without writing — wrapper sees EOF and exits.
                if let Some((_, write_fd)) = cgroup_sync_pipe {
                    unsafe { libc::close(write_fd) };
                }
                let _ = child.kill();
                let _ = child.wait();
                let _ = mgr.destroy(path);
                // Clean up remaining pipe FDs to prevent leaks.
                if let Some((read_fd, write_fd, _)) = audit_pipe {
                    unsafe {
                        libc::close(read_fd);
                        libc::close(write_fd);
                    }
                }
                if let Some((read_fd, write_fd)) = dns_audit_pipe {
                    unsafe {
                        libc::close(read_fd);
                        libc::close(write_fd);
                    }
                }
                if let Some((read_fd, write_fd)) = pid_report_pipe {
                    unsafe {
                        libc::close(read_fd);
                        libc::close(write_fd);
                    }
                }
                if let Some((read_fd, write_fd)) = unotify_audit_pipe {
                    unsafe {
                        libc::close(read_fd);
                        libc::close(write_fd);
                    }
                }
                #[cfg(unix)]
                if let Some(m) = pty_master_fd {
                    unsafe { libc::close(m) };
                }
                return Err(Error::Cgroup(format!("add_pid failed: {e}")));
            }
        }

        // ── Signal cgroup readiness to wrapper ────────────────────
        if let Some((_, write_fd)) = cgroup_sync_pipe {
            // Write a single byte to unblock the wrapper, then close.
            unsafe { libc::write(write_fd, [1u8].as_ptr().cast(), 1) };
            unsafe { libc::close(write_fd) };
        }

        // ── Read wrapper audit pipe ────────────────────────────────
        // Close write end in parent (essential — otherwise EOF never
        // arrives). Then read all lines until EOF. The wrapper writes
        // events before execve; the write end closes at exec (CLOEXEC
        // is cleared, but the wrapper explicitly closes it).
        if let Some((read_fd, write_fd, _)) = audit_pipe {
            // SAFETY: write_fd is a valid descriptor from pipe().
            unsafe { libc::close(write_fd) };
            let wrapper_failed = validate_wrapper_audit(read_fd);
            // SAFETY: read_fd is a valid descriptor from pipe().
            unsafe { libc::close(read_fd) };

            if wrapper_failed {
                let _ = child.kill();
                let _ = child.wait();
                if let Some((r, w)) = pid_report_pipe {
                    unsafe {
                        libc::close(r);
                        libc::close(w);
                    }
                }
                if let Some((r, w)) = dns_audit_pipe {
                    unsafe {
                        libc::close(r);
                        libc::close(w);
                    }
                }
                if let Some((r, w)) = unotify_audit_pipe {
                    unsafe {
                        libc::close(r);
                        libc::close(w);
                    }
                }
                #[cfg(unix)]
                if let Some(m) = pty_master_fd {
                    unsafe { libc::close(m) };
                }
                if let Some(ref path) = cgroup_path {
                    if let Some(ref mgr) = self.cgroup_mgr {
                        let _ = mgr.destroy(path);
                    }
                }
                return Err(Error::Process(
                    "wrapper reported sandbox layer failure".into(),
                ));
            }
        }

        // ── Read PID report pipe ──────────────────────────────────
        // The wrapper parent writes the target's host PID (4 bytes,
        // little-endian i32) after the audit events. Read it after
        // validate_wrapper_audit to avoid deadlock.
        if let Some((read_fd, write_fd)) = pid_report_pipe {
            unsafe { libc::close(write_fd) };
            let mut buf = [0u8; 4];
            let n = loop {
                let ret = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), 4) };
                if ret >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    break ret;
                }
            };
            unsafe { libc::close(read_fd) };
            if n == 4 {
                let target_pid = i32::from_le_bytes(buf);
                if target_pid > 0 {
                    log::debug!("pidns: target host PID = {target_pid}");
                    let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, target_pid, 0) };
                    if ret >= 0 {
                        pidfd =
                            Some(unsafe { std::os::unix::io::OwnedFd::from_raw_fd(ret as i32) });
                    } else {
                        log::warn!(
                            "pidns: pidfd_open for target failed: {}",
                            std::io::Error::last_os_error()
                        );
                        pidfd = None;
                    }
                    stored_target_pid = Some(target_pid as u32);
                } else {
                    log::warn!("pidns: invalid target PID from report pipe: {target_pid}");
                }
            } else {
                log::warn!("pidns: failed to read target PID from report pipe");
            }
        }

        // Close DNS audit pipe write end in parent. The read end is
        // kept open — Process::wait() reads it after the child exits.
        let dns_audit_read_fd = if let Some((read_fd, write_fd)) = dns_audit_pipe {
            unsafe { libc::close(write_fd) };
            Some(unsafe { std::os::unix::io::OwnedFd::from_raw_fd(read_fd) })
        } else {
            None
        };

        // Close unotify audit pipe write end in parent.
        let unotify_audit_read_fd = if let Some((read_fd, write_fd)) = unotify_audit_pipe {
            unsafe { libc::close(write_fd) };
            Some(unsafe { std::os::unix::io::OwnedFd::from_raw_fd(read_fd) })
        } else {
            None
        };

        // ── Emit ProcessStarted ────────────────────────────────────
        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::ProcessStarted {
                timestamp: ctx.timestamp(),
                pid: stored_target_pid.unwrap_or(child.id()),
            })?;
        }

        // Defuse the connect proxy guard — ownership transfers to
        // Process which handles cleanup in its Drop impl.
        connect_proxy_guard.defuse();

        Ok(Process {
            child: crate::process::ChildHandle::Managed(child),
            tmp_dir: tmp_guard.defuse(),
            cgroup_path,
            cgroup_mgr: self.cgroup_mgr.clone(),
            dns_audit_pipe: dns_audit_read_fd,
            unotify_audit_pipe: unotify_audit_read_fd,
            pidfd,
            target_pid: stored_target_pid,
            waited: false,
            connect_proxy_pid: connect_proxy_pid_local,
            connect_proxy_pidfd: connect_proxy_pidfd_local,
            connect_proxy_socket: connect_proxy_socket_local,
            #[cfg(feature = "microvm")]
            passt: None,
            pty_master: pty_master_fd.map(|fd| {
                // SAFETY: fd is a valid master FD from openpty with CLOEXEC set.
                unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) }
            }),
            audit_ctx,
            final_stats: None,
        })
    }

    fn available(&self) -> crate::Result<()> {
        std::process::Command::new("unshare")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| {
                Error::Process(format!(
                    "unshare not found: {e} (required for network namespace isolation)"
                ))
            })?;
        Ok(())
    }

    fn netns_available(&self) -> bool {
        crate::netns::available()
    }

    fn cgroups_available(&self) -> bool {
        self.cgroup_mgr.is_some()
    }
}

/// Read and validate audit events from the wrapper binary's pipe.
///
/// The wrapper writes one JSON line per applied layer. We read until
/// EOF (the wrapper closes the FD before execve) and validate that
/// all expected layers were applied. Buffer bounded to 64 KiB to
/// prevent OOM from a compromised wrapper.
fn validate_wrapper_audit(read_fd: RawFd) -> bool {
    const MAX_BUF: usize = 64 * 1024;
    let mut buf = vec![0u8; MAX_BUF];
    let mut total = 0;

    loop {
        // SAFETY: read_fd is a valid descriptor, buf is valid memory.
        let n = unsafe {
            libc::read(
                read_fd,
                buf[total..].as_mut_ptr().cast::<libc::c_void>(),
                buf.len() - total,
            )
        };
        if n == 0 {
            break;
        }
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            log::warn!("wrapper audit pipe read error: {err}");
            break;
        }
        total += n as usize;
        if total >= MAX_BUF {
            log::warn!("wrapper audit pipe exceeded 64 KiB, truncating");
            break;
        }
    }

    if total == 0 {
        log::warn!("wrapper audit pipe: no events received (wrapper may have crashed)");
        return true;
    }

    let text = String::from_utf8_lossy(&buf[..total]);
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    log::info!("wrapper audit: received {} events", lines.len());

    let mut has_failures = false;
    for line in &lines {
        if line.contains(r#""status":"failed""#) {
            log::error!(
                "wrapper audit: layer failure reported: {}",
                sanitize_audit_string(line)
            );
            has_failures = true;
        }
    }
    has_failures
}
