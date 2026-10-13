//! Degraded sandbox for non-Linux, non-macOS platforms.
//!
//! Provides minimal isolation — only environment hardening. No Landlock,
//! no seccomp, no cgroups, no network namespace. Suitable for development
//! and testing only. Production workloads should use Linux.

use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::Arc;

use crate::audit::{
    AuditContext, AuditEvent, AuditVerbosity, SCHEMA_VERSION, SandboxLayer, SkipReason,
    sanitize_audit_string,
};
use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

/// Degraded sandbox (no OS-level isolation).
pub struct Other;

impl Sandbox for Other {
    fn launch(&self, cfg: &Config, cmd: &str, args: &[&str]) -> crate::Result<Process> {
        cfg.profile.validate_unix_socket_policy()?;
        if cfg.tty {
            return Err(crate::Error::Validation(
                "tty mode is not supported on this platform".into(),
            ));
        }

        // Validate task ID and work directory.
        crate::sanitize_task_id(&cfg.task_id)?;
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
                SandboxLayer::Rlimit,
                SandboxLayer::NoNewPrivs,
                SandboxLayer::Pdeathsig,
            ] {
                ctx.emit(AuditEvent::LayerSkipped {
                    timestamp: ctx.timestamp(),
                    layer,
                    reason: SkipReason::PlatformUnsupported,
                })?;
            }

            ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::Setsid,
                detail: None,
            })?;

            ctx.emit(AuditEvent::SandboxReady {
                timestamp: ctx.timestamp(),
                applied_layers: vec![
                    SandboxLayer::EnvFilter,
                    SandboxLayer::FdSanitization,
                    SandboxLayer::Setsid,
                ],
                skipped_layers: vec![
                    SandboxLayer::Landlock,
                    SandboxLayer::Seccomp,
                    SandboxLayer::Cgroup,
                    SandboxLayer::NetworkNamespace,
                    SandboxLayer::Rlimit,
                    SandboxLayer::NoNewPrivs,
                    SandboxLayer::Pdeathsig,
                ],
            })?;
        }

        let mut command = Command::new(cmd);
        command.args(args);

        if let Some(work_dir) = &cfg.work_dir {
            command.current_dir(work_dir);
        }

        let mut env_vars = crate::env::minimal_env(tmp_guard.path());
        let filter_result = crate::env::filter_caller_env(&cfg.env);
        env_vars.extend(filter_result.passed);

        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::EnvPolicy {
                timestamp: ctx.timestamp(),
                passed_keys: env_vars.iter().map(|(k, _)| k.clone()).collect(),
                injected_keys: Vec::new(),
                dropped: filter_result.dropped,
            })?;
        }

        command.env_clear();
        for (k, v) in &env_vars {
            command.env(k, v);
        }

        // stdin/stdout/stderr redirection.
        super::setup_stdio(&mut command, cfg.stdin, "stdin", Command::stdin)?;
        super::setup_stdio(&mut command, cfg.stdout, "stdout", Command::stdout)?;
        super::setup_stdio(&mut command, cfg.stderr, "stderr", Command::stderr)?;

        super::fd::validate_extra_fds(&cfg.extra_fds, cfg)?;
        let mut fds_to_inherit = std::mem::ManuallyDrop::new(cfg.extra_fds.clone());

        // SAFETY: pre_exec runs between fork and exec. Only async-signal-safe
        // functions are used (setsid, fcntl, dup2, close). ManuallyDrop
        // prevents free() on the Vec in the child process.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if !fds_to_inherit.is_empty() {
                    super::fd::remap_fds(&mut fds_to_inherit)?;
                }
                Ok(())
            });
        }

        let child = command
            .spawn()
            .map_err(|e| Error::Process(format!("start process: {e}")))?;

        if let Some(ref ctx) = audit_ctx {
            if let Err(e) = ctx.emit(AuditEvent::ProcessStarted {
                timestamp: ctx.timestamp(),
                pid: child.id(),
            }) {
                log::error!("audit emit failed: {e}");
            }
        }

        Ok(Process {
            child: crate::process::ChildHandle::Managed(child),
            tmp_dir: tmp_guard.defuse(),
            waited: false,
            pty_master: None,
            audit_ctx,
            final_stats: None,
        })
    }

    fn available(&self) -> crate::Result<()> {
        Err(Error::Process(format!(
            "platform {} has degraded sandbox security (development only)",
            std::env::consts::OS
        )))
    }

    fn netns_available(&self) -> bool {
        false
    }

    fn cgroups_available(&self) -> bool {
        false
    }
}
