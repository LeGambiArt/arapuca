//! Micro-VM sandbox implementation.
//!
//! Uses libkrun to launch sandboxed subprocesses inside lightweight
//! virtual machines. The VM provides hardware-enforced isolation
//! (separate kernel, separate address space) via KVM.

use std::ffi::CString;
use std::path::PathBuf;
use std::sync::Arc;

use crate::audit::{
    AuditContext, AuditEvent, AuditVerbosity, LayerDetail, SCHEMA_VERSION, SandboxLayer,
    SkipReason, sanitize_audit_string,
};
use crate::platform::Sandbox;
use crate::{Config, Error, Isolation, MicroVmConfig, Process};

/// A host↔guest path pair for a virtiofs volume mount.
pub(crate) struct VolumeMapping {
    pub host: PathBuf,
    pub guest: PathBuf,
}

/// Optional parameters for persistent VM launches (vsock + agent).
pub(crate) struct PersistentVmOpts<'a> {
    /// Directory containing the agent binary (mounted read-only at /agent).
    pub agent_bin_dir: &'a std::path::Path,
    /// Host-side Unix socket path for the vsock-mapped agent port.
    pub agent_sock_path: &'a std::path::Path,
    /// Nonce bytes to write to cidata for agent authentication.
    pub nonce: &'a [u8; crate::vm::protocol::NONCE_SIZE],
    /// Max lifetime in seconds (written to cidata for the agent).
    pub max_lifetime: Option<u64>,
}

/// Shell-quote a string for safe interpolation in `/bin/sh` scripts.
///
/// Uses POSIX single-quote wrapping: the string is enclosed in single
/// quotes, with internal single quotes escaped as `'\''`.
pub(crate) fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_./=:@,+".contains(&b))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Micro-VM sandbox implementation.
pub struct MicroVm;

impl MicroVm {
    pub fn new() -> crate::Result<Self> {
        Ok(Self)
    }
}

impl Sandbox for MicroVm {
    fn launch(&self, cfg: &Config, cmd: &str, args: &[&str]) -> crate::Result<Process> {
        if cfg.profile.deny_unix_sockets {
            return Err(crate::Error::Validation(
                "Unix socket denial is unavailable for MicroVm".into(),
            ));
        }
        let vm_cfg = match &cfg.profile.isolation {
            Isolation::MicroVm(c) => c,
            _ => {
                return Err(Error::MicroVm(
                    "MicroVm sandbox requires Isolation::MicroVm profile".into(),
                ));
            }
        };

        crate::sanitize_task_id(&cfg.task_id)?;

        // Pre-fork validation of write_files: validate before cloud-init
        // YAML generation to catch errors early with proper messages.
        // Post-fork validation in exec_vm_inner provides defense-in-depth.
        if vm_cfg.write_files.len() > crate::MAX_GUEST_WRITE_FILES {
            return Err(Error::MicroVm(format!(
                "too many write_files ({}, max {})",
                vm_cfg.write_files.len(),
                crate::MAX_GUEST_WRITE_FILES
            )));
        }
        for gf in &vm_cfg.write_files {
            crate::validate_guest_path(&gf.path)
                .map_err(|e| Error::MicroVm(format!("write_files: {e}")))?;
            if let Some(perms) = &gf.permissions {
                crate::validate_guest_permissions(perms)
                    .map_err(|e| Error::MicroVm(format!("write_files: {e}")))?;
            }
            crate::validate_guest_file_content(&gf.content)
                .map_err(|e| Error::MicroVm(format!("write_files: {e}")))?;
        }

        // TmpDirGuard ensures cleanup on any error path. Fork safety: the
        // child process in launch_vm() uses _exit(1), which does not run
        // Rust destructors, so the guard only cleans up in the parent.
        let tmp_guard = crate::env::TmpDirGuard::new(crate::env::make_tmp_dir(&cfg.task_id)?);

        let audit_ctx = cfg
            .audit_sink
            .as_ref()
            .map(|sink| AuditContext::new(Arc::clone(sink), cfg.audit_verbosity.clone()));

        // Emit SandboxInit.
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

        // Resolve the image.
        let image_source =
            cfg.profile.isolation.image_source().ok_or_else(|| {
                Error::MicroVm("MicroVm isolation requires an image source".into())
            })?;
        let cached = crate::images::resolve(image_source, &Default::default())?;

        // Create COW overlay so the template stays immutable.
        let overlay_dir = tmp_guard.path().join("vm");
        let overlay_path = crate::images::overlay::create_overlay(&cached.path, &overlay_dir)?;

        // Generate cloud-init datasource.
        let mut virtiofs_mounts = Vec::new();
        for (i, path) in cfg.profile.read_paths.iter().enumerate() {
            virtiofs_mounts.push((format!("ro{i}"), path.to_string_lossy().to_string(), "ro"));
        }
        for (i, path) in cfg.profile.write_paths.iter().enumerate() {
            virtiofs_mounts.push((
                format!("rw{i}"),
                path.to_string_lossy().to_string(),
                "defaults",
            ));
        }

        let mount_refs: Vec<(&str, &str, &str)> = virtiofs_mounts
            .iter()
            .map(|(t, m, o)| (t.as_str(), m.as_str(), *o))
            .collect();

        let wf_refs: Vec<crate::images::cloudinit::WriteFile<'_>> = vm_cfg
            .write_files
            .iter()
            .map(|gf| crate::images::cloudinit::WriteFile {
                path: &gf.path,
                content: &gf.content,
                permissions: gf.permissions.as_deref(),
            })
            .collect();

        let ci_cfg = crate::images::cloudinit::CloudInitConfig {
            hostname: &cfg.task_id,
            user: "agent",
            virtiofs_mounts: mount_refs,
            write_files: wf_refs,
            runcmd: None,
        };

        let ci_dir = crate::images::cloudinit::generate_datasource(&ci_cfg, tmp_guard.path())?;

        // Emit audit events.
        let mut applied_layers = Vec::new();
        let mut skipped_layers = Vec::new();

        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::LayerApplied {
                timestamp: ctx.timestamp(),
                layer: SandboxLayer::MicroVm,
                detail: Some(LayerDetail::MicroVm {
                    image_path: cached.path.to_string_lossy().into_owned(),
                    cpus: vm_cfg.cpus,
                    mem_mb: vm_cfg.mem_mb,
                }),
            })?;
        }
        applied_layers.push(SandboxLayer::MicroVm);

        // Skip all process-level layers — superseded by VM isolation.
        for layer in [
            SandboxLayer::Landlock,
            SandboxLayer::Seccomp,
            SandboxLayer::Cgroup,
            SandboxLayer::NetworkNamespace,
            SandboxLayer::Rlimit,
            SandboxLayer::NoNewPrivs,
            SandboxLayer::Setsid,
            SandboxLayer::Pdeathsig,
            SandboxLayer::FdSanitization,
        ] {
            if let Some(ref ctx) = audit_ctx {
                ctx.emit(AuditEvent::LayerSkipped {
                    timestamp: ctx.timestamp(),
                    layer: layer.clone(),
                    reason: SkipReason::PlatformUnsupported,
                })?;
            }
            skipped_layers.push(layer);
        }

        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::SandboxReady {
                timestamp: ctx.timestamp(),
                applied_layers: applied_layers.clone(),
                skipped_layers: skipped_layers.clone(),
            })?;
        }

        // Start networking if allowed (use_netns=false means allow network).
        let passt = if !cfg.profile.use_netns {
            match super::microvm_net::start_passt() {
                Ok(handle) => Some(handle),
                Err(e) => {
                    log::warn!("passt not available, VM will have no network: {e}");
                    None
                }
            }
        } else {
            None
        };

        let net_fd = passt.as_ref().map(|p| p.parent_fd);
        let net_ips = passt.as_ref().map(|p| {
            (
                p.net_info.guest_ip.clone(),
                p.net_info.router_ip.clone(),
                p.net_info.dns_servers.clone(),
            )
        });

        // Fork and launch the VM in the child.
        // Build the full command string for the init script.
        // Each component is shell-quoted to prevent injection.
        let full_cmd = if !cmd.is_empty() {
            if args.is_empty() {
                shell_quote(cmd)
            } else {
                let quoted_args: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
                format!("{} {}", shell_quote(cmd), quoted_args.join(" "))
            }
        } else {
            String::new()
        };

        let read_vols: Vec<VolumeMapping> = cfg
            .profile
            .read_paths
            .iter()
            .map(|p| VolumeMapping {
                host: p.clone(),
                guest: p.clone(),
            })
            .collect();
        let write_vols: Vec<VolumeMapping> = cfg
            .profile
            .write_paths
            .iter()
            .map(|p| VolumeMapping {
                host: p.clone(),
                guest: p.clone(),
            })
            .collect();

        let filter_result = crate::env::filter_caller_env(&cfg.env);
        if let Some(ref ctx) = audit_ctx {
            ctx.emit(AuditEvent::EnvPolicy {
                timestamp: ctx.timestamp(),
                passed_keys: filter_result
                    .passed
                    .iter()
                    .map(|(k, _)| k.clone())
                    .collect(),
                injected_keys: Vec::new(),
                dropped: filter_result.dropped,
            })?;
        }

        let mut process = launch_vm(
            vm_cfg,
            &overlay_path,
            &ci_dir,
            &cached.metadata,
            &read_vols,
            &write_vols,
            &full_cmd,
            &filter_result.passed,
            net_fd,
            net_ips.as_ref(),
            tmp_guard.path(),
            audit_ctx,
            &vm_cfg.write_files,
        )?;

        // Store passt in the Process for deterministic cleanup.
        process.passt = passt;

        // Disarm the guard — launch_vm already stored the path in Process::tmp_dir.
        tmp_guard.defuse();

        Ok(process)
    }

    fn available(&self) -> crate::Result<()> {
        // Check /dev/kvm exists and is accessible.
        std::fs::File::open("/dev/kvm").map_err(|e| {
            Error::MicroVm(format!(
                "/dev/kvm: {e} (KVM not available or no permission)"
            ))
        })?;
        // Check qemu-img is available.
        std::process::Command::new("qemu-img")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| Error::MicroVm(format!("qemu-img not found: {e}")))?;
        Ok(())
    }

    fn netns_available(&self) -> bool {
        true
    }

    fn cgroups_available(&self) -> bool {
        false
    }
}

#[allow(clippy::too_many_arguments)]
fn launch_vm(
    vm_cfg: &MicroVmConfig,
    overlay_path: &std::path::Path,
    ci_dir: &std::path::Path,
    meta: &crate::images::ImageMetadata,
    read_vols: &[VolumeMapping],
    write_vols: &[VolumeMapping],
    cmd: &str,
    env: &[(String, String)],
    net_fd: Option<i32>,
    net_ips: Option<&(String, String, Vec<String>)>,
    tmp_dir: &std::path::Path,
    audit_ctx: Option<AuditContext>,
    write_files: &[crate::GuestFile],
) -> crate::Result<Process> {
    // SAFETY: the passt DHCP reader thread may still be alive, but
    // it only holds a BufReader on passt's stderr pipe and does not
    // share mutable state with the child path. The child calls only
    // setsid/prctl (async-signal-safe) then krun_start_enter (which
    // replaces the process) or _exit.
    let child_pid = unsafe { libc::fork() };

    if child_pid < 0 {
        return Err(Error::MicroVm(format!(
            "fork: {}",
            std::io::Error::last_os_error()
        )));
    }

    if child_pid == 0 {
        // ── VM child ──────────────────────────────────────────
        // Apply process-sandbox invariants: setsid, pdeathsig,
        // NO_NEW_PRIVS, and FD sanitization.
        // SAFETY: all calls are async-signal-safe. Error reporting
        // uses raw write(2) to avoid mutex/allocation in eprintln!.
        unsafe {
            if libc::setsid() == -1 {
                let msg = b"arapuca: microvm: setsid failed\n";
                libc::write(2, msg.as_ptr().cast(), msg.len());
                libc::_exit(1);
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                let msg = b"arapuca: microvm: prctl PDEATHSIG failed\n";
                libc::write(2, msg.as_ptr().cast(), msg.len());
                libc::_exit(1);
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                let msg = b"arapuca: microvm: prctl NO_NEW_PRIVS failed\n";
                libc::write(2, msg.as_ptr().cast(), msg.len());
                libc::_exit(1);
            }
            if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
                let msg = b"arapuca: microvm: prctl DUMPABLE failed\n";
                libc::write(2, msg.as_ptr().cast(), msg.len());
                libc::_exit(1);
            }

            // Close all FDs except stdin/stdout/stderr and the
            // passt parent_fd (if networking is enabled).
            let keep_fd = net_fd.unwrap_or(-1);
            if keep_fd >= 3 {
                if keep_fd > 3 {
                    libc::syscall(libc::SYS_close_range, 3u32, (keep_fd - 1) as u32, 0u32);
                }
                libc::syscall(libc::SYS_close_range, (keep_fd + 1) as u32, u32::MAX, 0u32);
            } else {
                libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
            }
        }

        exec_vm(
            vm_cfg,
            overlay_path,
            ci_dir,
            meta,
            read_vols,
            write_vols,
            cmd,
            env,
            net_fd,
            net_ips,
            None,
            write_files,
        );
    }

    // ── Parent ────────────────────────────────────────────────
    if let Some(ref ctx) = audit_ctx {
        let _ = ctx.emit(AuditEvent::ProcessStarted {
            timestamp: ctx.timestamp(),
            pid: child_pid as u32,
        });
    }

    // Open pidfd for the forked child (race-free — direct parent,
    // child is guaranteed alive immediately after fork).
    #[cfg(target_os = "linux")]
    let pidfd = {
        let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) };
        if ret >= 0 {
            Some(unsafe { std::os::unix::io::OwnedFd::from_raw_fd(ret as i32) })
        } else {
            None
        }
    };

    Ok(Process {
        child: crate::process::ChildHandle::Forked(child_pid as u32),
        tmp_dir: tmp_dir.to_path_buf(),
        #[cfg(target_os = "linux")]
        cgroup_path: None,
        #[cfg(target_os = "linux")]
        cgroup_mgr: None,
        #[cfg(target_os = "linux")]
        dns_audit_pipe: None,
        #[cfg(target_os = "linux")]
        pidfd,
        #[cfg(target_os = "linux")]
        target_pid: None,
        waited: false,
        passt: None,
        pty_master: None,
        audit_ctx,
        final_stats: None,
    })
}

/// Execute the VM in the current process (called from the forked child).
/// This function never returns — it replaces the process with the VM.
#[allow(clippy::too_many_arguments)]
pub(crate) fn exec_vm(
    vm_cfg: &MicroVmConfig,
    overlay_path: &std::path::Path,
    ci_dir: &std::path::Path,
    meta: &crate::images::ImageMetadata,
    read_vols: &[VolumeMapping],
    write_vols: &[VolumeMapping],
    cmd: &str,
    env: &[(String, String)],
    net_fd: Option<i32>,
    net_ips: Option<&(String, String, Vec<String>)>,
    persistent: Option<&PersistentVmOpts<'_>>,
    write_files: &[crate::GuestFile],
) -> ! {
    if let Err(e) = exec_vm_inner(
        vm_cfg,
        overlay_path,
        ci_dir,
        meta,
        read_vols,
        write_vols,
        cmd,
        env,
        net_fd,
        net_ips,
        persistent,
        write_files,
    ) {
        // Post-fork: use raw write(2) to avoid mutex/allocation deadlocks.
        // We lose the dynamic error message but avoid the risk of hanging
        // the child if the parent held the stderr lock at fork time.
        let _ = e;
        let msg = b"arapuca: microvm: exec_vm failed\n";
        unsafe { libc::write(2, msg.as_ptr().cast(), msg.len()) };
    }
    // SAFETY: we are in the forked child.
    unsafe { libc::_exit(1) }
}

#[allow(clippy::too_many_arguments)]
fn exec_vm_inner(
    vm_cfg: &MicroVmConfig,
    overlay_path: &std::path::Path,
    ci_dir: &std::path::Path,
    meta: &crate::images::ImageMetadata,
    read_vols: &[VolumeMapping],
    write_vols: &[VolumeMapping],
    cmd: &str,
    env: &[(String, String)],
    net_fd: Option<i32>,
    net_ips: Option<&(String, String, Vec<String>)>,
    persistent: Option<&PersistentVmOpts<'_>>,
    write_files: &[crate::GuestFile],
) -> crate::Result<()> {
    // SAFETY: all krun_sys calls operate on a context ID and take
    // C strings. The context is process-local (this is the forked
    // child). Return values are checked.

    let ctx_raw = unsafe { krun_sys::krun_create_ctx() };
    if ctx_raw < 0 {
        return Err(Error::MicroVm(format!(
            "krun_create_ctx failed (ret={ctx_raw})"
        )));
    }
    let ctx = ctx_raw as u32;

    let cpus = vm_cfg.cpus.min(255) as u8;
    let ret = unsafe { krun_sys::krun_set_vm_config(ctx, cpus, vm_cfg.mem_mb) };
    if ret < 0 {
        return Err(Error::MicroVm("krun_set_vm_config failed".into()));
    }

    use std::os::unix::ffi::OsStrExt;

    // Add the overlay disk.
    let disk_path = CString::new(overlay_path.as_os_str().as_bytes())
        .map_err(|_| Error::MicroVm("invalid disk path".into()))?;
    let disk_label =
        CString::new("root").map_err(|_| Error::MicroVm("CString: disk label".into()))?;

    let ret = unsafe {
        krun_sys::krun_add_disk2(
            ctx,
            disk_label.as_ptr(),
            disk_path.as_ptr(),
            krun_sys::KRUN_DISK_FORMAT_QCOW2,
            false,
        )
    };
    if ret < 0 {
        return Err(Error::MicroVm("krun_add_disk2 failed".into()));
    }

    // Set root disk remount (with optional mount options for e.g. btrfs subvolumes).
    let device = CString::new(meta.root_device.as_bytes())
        .map_err(|_| Error::MicroVm("invalid root_device".into()))?;
    let fstype = CString::new(meta.fstype.as_bytes())
        .map_err(|_| Error::MicroVm("invalid fstype".into()))?;
    let mount_opts = meta
        .mount_options
        .as_ref()
        .map(|o| CString::new(o.as_bytes()))
        .transpose()
        .map_err(|_| Error::MicroVm("invalid mount_options".into()))?;

    let ret = unsafe {
        krun_sys::krun_set_root_disk_remount(
            ctx,
            device.as_ptr(),
            fstype.as_ptr(),
            mount_opts.as_ref().map_or(std::ptr::null(), |o| o.as_ptr()),
        )
    };
    if ret < 0 {
        return Err(Error::MicroVm("krun_set_root_disk_remount failed".into()));
    }

    // Add cloud-init datasource as a virtio-fs share.
    let ci_tag =
        CString::new("cidata").map_err(|_| Error::MicroVm("CString: cidata tag".into()))?;
    let ci_path = CString::new(ci_dir.as_os_str().as_bytes())
        .map_err(|_| Error::MicroVm("invalid cloud-init path".into()))?;

    let ret = unsafe { krun_sys::krun_add_virtiofs(ctx, ci_tag.as_ptr(), ci_path.as_ptr()) };
    if ret < 0 {
        return Err(Error::MicroVm("krun_add_virtiofs (cidata) failed".into()));
    }

    // Add read-only paths as virtio-fs shares (host paths).
    for (i, vol) in read_vols.iter().enumerate() {
        let tag =
            CString::new(format!("ro{i}")).map_err(|_| Error::MicroVm("CString: ro tag".into()))?;
        let host = CString::new(vol.host.as_os_str().as_bytes())
            .map_err(|_| Error::MicroVm(format!("invalid read path: {}", vol.host.display())))?;
        let ret = unsafe { krun_sys::krun_add_virtiofs(ctx, tag.as_ptr(), host.as_ptr()) };
        if ret < 0 {
            return Err(Error::MicroVm(format!("krun_add_virtiofs (ro{i}) failed")));
        }
    }

    // Add read-write paths as virtio-fs shares (host paths).
    for (i, vol) in write_vols.iter().enumerate() {
        let tag =
            CString::new(format!("rw{i}")).map_err(|_| Error::MicroVm("CString: rw tag".into()))?;
        let host = CString::new(vol.host.as_os_str().as_bytes())
            .map_err(|_| Error::MicroVm(format!("invalid write path: {}", vol.host.display())))?;
        let ret = unsafe { krun_sys::krun_add_virtiofs(ctx, tag.as_ptr(), host.as_ptr()) };
        if ret < 0 {
            return Err(Error::MicroVm(format!("krun_add_virtiofs (rw{i}) failed")));
        }
    }

    // Configure networking if a passt FD was provided.
    if let Some(fd) = net_fd {
        let mut mac = super::microvm_net::random_mac();
        let ret = unsafe {
            krun_sys::krun_add_net_unixstream(
                ctx,
                std::ptr::null(),
                fd,
                mac.as_mut_ptr(),
                krun_sys::COMPAT_NET_FEATURES,
                0,
            )
        };
        if ret < 0 {
            return Err(Error::MicroVm("krun_add_net_unixstream failed".into()));
        }
    }

    // For persistent VMs: add agent-bin virtiofs share and vsock port.
    if let Some(opts) = persistent {
        use std::os::unix::ffi::OsStrExt as _;

        // Read-only virtiofs share for the agent binary.
        let agent_tag = CString::new("agent-bin")
            .map_err(|_| Error::MicroVm("CString: agent-bin tag".into()))?;
        let agent_path = CString::new(opts.agent_bin_dir.as_os_str().as_bytes())
            .map_err(|_| Error::MicroVm("invalid agent bin path".into()))?;
        let ret =
            unsafe { krun_sys::krun_add_virtiofs(ctx, agent_tag.as_ptr(), agent_path.as_ptr()) };
        if ret < 0 {
            return Err(Error::MicroVm(
                "krun_add_virtiofs (agent-bin) failed".into(),
            ));
        }

        // Disable the implicit vsock/TSI device and add an explicit
        // one with no TSI features (prevents uncontrolled guest→host).
        let ret = unsafe { krun_sys::krun_disable_implicit_vsock(ctx) };
        if ret < 0 {
            return Err(Error::MicroVm("krun_disable_implicit_vsock failed".into()));
        }
        let ret = unsafe { krun_sys::krun_add_vsock(ctx, 0) };
        if ret < 0 {
            return Err(Error::MicroVm("krun_add_vsock failed".into()));
        }

        // Map guest vsock port → host Unix socket (guest listens).
        let sock_path = CString::new(opts.agent_sock_path.as_os_str().as_bytes())
            .map_err(|_| Error::MicroVm("invalid agent socket path".into()))?;
        let ret = unsafe {
            krun_sys::krun_add_vsock_port2(
                ctx,
                crate::vm::protocol::AGENT_VSOCK_PORT,
                sock_path.as_ptr(),
                true, // listen=true: guest listens, host connects
            )
        };
        if ret < 0 {
            return Err(Error::MicroVm("krun_add_vsock_port2 failed".into()));
        }

        // Write nonce and max_lifetime to cidata for the agent.
        let nonce_path = ci_dir.join("nonce");
        std::fs::write(&nonce_path, opts.nonce)
            .map_err(|e| Error::MicroVm(format!("write nonce: {e}")))?;
        if let Some(lt) = opts.max_lifetime {
            let lt_path = ci_dir.join("max_lifetime");
            std::fs::write(&lt_path, lt.to_string())
                .map_err(|e| Error::MicroVm(format!("write max_lifetime: {e}")))?;
        }
    }

    // Build an init script that mounts virtio-fs shares, configures
    // networking, and runs the user's command. We can't use /sbin/init
    // (systemd) because libkrun's boot environment doesn't provide the
    // kernel command line systemd expects.
    let mut init_script = String::from("#!/bin/sh\nset -e\n");

    // Mount pseudo-filesystems (no systemd to do this for us).
    init_script.push_str("mount -t proc proc /proc\n");
    init_script.push_str("mount -t sysfs sysfs /sys\n");
    init_script.push_str("mkdir -p /dev/pts\n");
    init_script
        .push_str("mount -t devpts devpts /dev/pts -o newinstance,ptmxmode=0666,nosuid,noexec\n");
    init_script.push_str("ln -sf pts/ptmx /dev/ptmx\n");
    init_script.push_str("mount -t tmpfs tmpfs /run\n");
    init_script.push_str("mkdir -p /run/lock\n");

    // Mount the cloud-init data directory.
    init_script.push_str("mkdir -p /cidata && mount -t virtiofs cidata /cidata\n");

    // Mount read-only shares (guest paths).
    for (i, vol) in read_vols.iter().enumerate() {
        let gp = shell_quote(&vol.guest.to_string_lossy());
        init_script.push_str(&format!(
            "mkdir -p {gp} && mount -t virtiofs -o ro ro{i} {gp}\n"
        ));
    }

    // Mount read-write shares (guest paths).
    for (i, vol) in write_vols.iter().enumerate() {
        let gp = shell_quote(&vol.guest.to_string_lossy());
        init_script.push_str(&format!("mkdir -p {gp} && mount -t virtiofs rw{i} {gp}\n"));
    }

    // Configure networking if passt provided guest/router IPs.
    // IPs are validated via Ipv4Addr in microvm_net.rs; shell_quote
    // is applied here for defense-in-depth.
    if let Some((guest_ip, router_ip, dns_servers)) = net_ips {
        let gip = shell_quote(guest_ip);
        let rip = shell_quote(router_ip);
        init_script.push_str("ip link set up dev lo\n");
        init_script.push_str(&format!("ip addr add {gip}/24 dev eth0\n"));
        init_script.push_str("ip link set up dev eth0\n");
        init_script.push_str(&format!("ip route add default via {rip}\n"));
        init_script.push_str("rm -f /etc/resolv.conf\n");
        if dns_servers.is_empty() {
            init_script.push_str(&format!("echo 'nameserver {rip}' > /etc/resolv.conf\n"));
        } else {
            for (i, ns) in dns_servers.iter().enumerate() {
                let redir = if i == 0 { ">" } else { ">>" };
                let qns = shell_quote(ns);
                init_script.push_str(&format!(
                    "echo 'nameserver {qns}' {redir} /etc/resolv.conf\n"
                ));
            }
        }
    }

    // Fix directory permissions that the cloud image ships read-only
    // (btrfs snapshots). Without this, tools that write to /root or
    // run RPM scriptlets fail.
    init_script.push_str(
        "chmod 755 /root /usr/bin /usr/lib /usr/lib64 /usr/sbin /usr/libexec 2>/dev/null\n",
    );

    // Write guest files from the write_files configuration.
    // Defense-in-depth: re-validate here in the post-fork child in case
    // a future code path bypasses the pre-fork validation in launch().
    for gf in write_files {
        crate::validate_guest_path(&gf.path)
            .map_err(|e| Error::MicroVm(format!("write_files: {e}")))?;
        if let Some(perms) = &gf.permissions {
            crate::validate_guest_permissions(perms)
                .map_err(|e| Error::MicroVm(format!("write_files: {e}")))?;
        }
        crate::validate_guest_file_content(&gf.content)
            .map_err(|e| Error::MicroVm(format!("write_files: {e}")))?;
        let qpath = shell_quote(&gf.path);
        if let Some(parent) = std::path::Path::new(&gf.path).parent() {
            if parent != std::path::Path::new("/") {
                let qdir = shell_quote(&parent.to_string_lossy());
                init_script.push_str(&format!("mkdir -p -- {qdir}\n"));
            }
        }
        let qcontent = shell_quote(&gf.content);
        init_script.push_str(&format!("printf '%s' {qcontent} > {qpath}\n"));
        if let Some(perms) = &gf.permissions {
            let qperms = shell_quote(perms);
            init_script.push_str(&format!("chmod -- {qperms} {qpath}\n"));
        }
    }

    // For persistent VMs: mount agent-bin share and start the agent.
    // For ephemeral VMs: exec the user's command directly.
    if persistent.is_some() {
        init_script.push_str("mkdir -p /agent && mount -t virtiofs -o ro agent-bin /agent\n");
        init_script.push_str("mount -o remount,ro /cidata\n");
        init_script.push_str("/agent/arapuca-agent &\n");
        init_script.push_str("AGENT_PID=$!\n");
        init_script.push_str("wait $AGENT_PID\n");
    } else {
        let user_cmd = if !cmd.is_empty() {
            format!("exec {cmd}")
        } else {
            "exec /bin/sh".to_string()
        };
        init_script.push_str(&user_cmd);
        init_script.push('\n');
    }

    // Write the init script to the cidata directory on the host.
    // It will be accessible inside the VM after mounting the cidata
    // virtio-fs share.
    let init_script_path = ci_dir.join("init.sh");
    std::fs::write(&init_script_path, &init_script)
        .map_err(|e| Error::MicroVm(format!("write init script: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&init_script_path)
            .map_err(|e| Error::MicroVm(format!("init script metadata: {e}")))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&init_script_path, perms)
            .map_err(|e| Error::MicroVm(format!("chmod init script: {e}")))?;
    }

    // Use a short ASCII-only bootstrap to mount cidata and exec the
    // init script. libkrun passes argv/env through the kernel command
    // line which only supports ASCII — the real script lives on disk.
    let c_cmd = CString::new("/bin/sh").map_err(|_| Error::MicroVm("CString: /bin/sh".into()))?;
    let c_arg_flag = CString::new("-c").map_err(|_| Error::MicroVm("CString: -c".into()))?;
    let c_arg_bootstrap = CString::new(
        "mkdir -p /cidata && mount -t virtiofs cidata /cidata && exec /bin/sh /cidata/init.sh",
    )
    .map_err(|_| Error::MicroVm("CString: bootstrap cmd".into()))?;

    let mut c_env: Vec<CString> = Vec::new();
    c_env.push(CString::new("HOME=/root").map_err(|_| Error::MicroVm("CString: HOME".into()))?);
    c_env.push(
        CString::new("PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin")
            .map_err(|_| Error::MicroVm("CString: PATH".into()))?,
    );
    c_env.push(CString::new("TERM=xterm").map_err(|_| Error::MicroVm("CString: TERM".into()))?);
    for (k, v) in env {
        if let Ok(kv) = CString::new(format!("{k}={v}")) {
            c_env.push(kv);
        }
    }

    let mut envp: Vec<*const libc::c_char> = c_env.iter().map(|s| s.as_ptr()).collect();
    envp.push(std::ptr::null());

    let argv: Vec<*const libc::c_char> = vec![
        c_arg_flag.as_ptr(),
        c_arg_bootstrap.as_ptr(),
        std::ptr::null(),
    ];

    let ret = unsafe { krun_sys::krun_set_exec(ctx, c_cmd.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    if ret < 0 {
        return Err(Error::MicroVm("krun_set_exec failed".into()));
    }

    // Start the VM. This replaces the current process.
    let ret = unsafe { krun_sys::krun_start_enter(ctx) };
    // If we get here, start_enter failed.
    Err(Error::MicroVm(format!(
        "krun_start_enter failed (ret={ret})"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microvm_available_check() {
        let vm = MicroVm::new().unwrap();
        let result = vm.available();
        match &result {
            Ok(()) => eprintln!("microvm: available (KVM + qemu-img)"),
            Err(e) => eprintln!("microvm: not available: {e}"),
        }
    }

    #[test]
    fn shell_quote_passthrough() {
        assert_eq!(shell_quote("hello"), "hello");
        assert_eq!(shell_quote("/usr/bin/curl"), "/usr/bin/curl");
        assert_eq!(shell_quote("key=value"), "key=value");
    }

    #[test]
    fn shell_quote_empty() {
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn shell_quote_spaces() {
        assert_eq!(shell_quote("hello world"), "'hello world'");
    }

    #[test]
    fn shell_quote_single_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn shell_quote_semicolons() {
        assert_eq!(shell_quote("a; rm -rf /"), "'a; rm -rf /'");
    }

    #[test]
    fn shell_quote_dollar_backtick() {
        assert_eq!(shell_quote("$(evil)"), "'$(evil)'");
        assert_eq!(shell_quote("`evil`"), "'`evil`'");
    }

    #[test]
    fn shell_quote_newline() {
        assert_eq!(shell_quote("a\nb"), "'a\nb'");
    }
}
