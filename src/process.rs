//! Sandboxed process lifecycle.
//!
//! Represents a running sandboxed subprocess with methods for waiting,
//! reading resource usage, and cleanup.

use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::io::AsFd;

use crate::ResourceUsage;
use crate::audit::{AuditContext, AuditEvent};

/// Child process variant — either a std::process::Child or a raw
/// PID from fork() (used by the micro-VM path where we fork
/// directly instead of going through Command).
#[cfg(not(windows))]
pub(crate) enum ChildHandle {
    Managed(std::process::Child),
    #[cfg_attr(not(feature = "microvm"), allow(dead_code))]
    Forked(u32),
}

/// A running sandboxed subprocess.
pub struct Process {
    /// The child process handle (Unix platforms).
    #[cfg(not(windows))]
    pub(crate) child: ChildHandle,
    /// Process handle (Windows). Owned — CloseHandle on drop.
    #[cfg(windows)]
    pub(crate) process_handle: std::os::windows::io::OwnedHandle,
    /// Process ID (Windows).
    #[cfg(windows)]
    pub(crate) process_id: u32,
    /// Sandbox-created temp directory (HOME for the subprocess).
    pub(crate) tmp_dir: PathBuf,
    /// Cgroup path (None if no cgroup). Linux only.
    #[cfg(target_os = "linux")]
    pub(crate) cgroup_path: Option<PathBuf>,
    /// DNS audit pipe read end. Read in wait() after child exits.
    #[cfg(target_os = "linux")]
    pub(crate) dns_audit_pipe: Option<std::os::unix::io::OwnedFd>,
    /// Unotify audit pipe read end. Read in wait() after child exits.
    #[cfg(target_os = "linux")]
    pub(crate) unotify_audit_pipe: Option<std::os::unix::io::OwnedFd>,
    /// pidfd for the sandboxed process (Linux 5.3+). Enables
    /// race-free signaling via pidfd_send_signal. None on older
    /// kernels or non-Linux platforms.
    #[cfg(target_os = "linux")]
    pub(crate) pidfd: Option<std::os::unix::io::OwnedFd>,
    /// Host PID of the actual target when PID namespace is active.
    /// Without pidns, this is None and pid() returns child.id().
    #[cfg(target_os = "linux")]
    pub(crate) target_pid: Option<u32>,
    /// Whether the target runs in a PID namespace (namespace
    /// collapse reaps orphans there; the process-group sweep is
    /// skipped). With the supervisor topology the pid report exists
    /// for every supervisor launch, so target_pid alone no longer
    /// distinguishes pidns runs from plain ones.
    #[cfg(target_os = "linux")]
    pub(crate) pidns_active: bool,
    /// Set to true after wait() successfully reaps the child.
    /// Guards signal() against PID-recycling races on the kill()
    /// fallback path.
    pub(crate) waited: bool,
    /// Launch timestamp for macOS Seatbelt denial log querying.
    #[cfg(target_os = "macos")]
    pub(crate) launch_timestamp: Option<std::time::SystemTime>,
    /// Cancellation flag for macOS memory monitor thread.
    #[cfg(target_os = "macos")]
    pub(crate) monitor_cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Join handle for macOS memory monitor thread.
    #[cfg(target_os = "macos")]
    pub(crate) monitor_handle: Option<std::thread::JoinHandle<()>>,
    /// Reference to the cgroup manager for stats/cleanup. Linux only.
    #[cfg(target_os = "linux")]
    pub(crate) cgroup_mgr: Option<std::sync::Arc<crate::cgroup::CgroupManager>>,
    /// Job Object handle. Kept alive for JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE:
    /// when the handle closes (drop or parent crash), Windows kills all
    /// processes in the Job Object.
    #[cfg(windows)]
    #[allow(dead_code)]
    pub(crate) job_handle: Option<std::os::windows::io::OwnedHandle>,
    /// AppContainer profile name for cleanup.
    #[cfg(windows)]
    pub(crate) container_name: Option<String>,
    /// Saved DACLs for restoration during cleanup.
    #[cfg(windows)]
    pub(crate) saved_dacls: Vec<crate::platform::windows::SavedDacl>,
    /// CONNECT proxy child PID (Linux only). Forked by the library
    /// when `Config::allowed_hosts` is non-empty. Killed on drop.
    #[cfg(target_os = "linux")]
    pub(crate) connect_proxy_pid: Option<i32>,
    /// pidfd for the CONNECT proxy child. Closed on drop.
    #[cfg(target_os = "linux")]
    pub(crate) connect_proxy_pidfd: Option<i32>,
    /// Socket path for the CONNECT proxy (for cleanup).
    #[cfg(target_os = "linux")]
    pub(crate) connect_proxy_socket: Option<PathBuf>,
    /// Passt network proxy handle (micro-VM only). Kept alive for
    /// the VM's lifetime; killed on cleanup/drop.
    #[cfg(all(target_os = "linux", feature = "microvm"))]
    pub(crate) passt: Option<crate::platform::microvm_net::PasstHandle>,
    /// PTY master FD (parent side). Present when `Config::tty` was set.
    /// The caller should proxy I/O on this FD via `pty_master()`.
    /// Closed automatically on drop.
    #[cfg(unix)]
    pub(crate) pty_master: Option<std::os::unix::io::OwnedFd>,
    /// Audit context for emitting lifecycle events.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) audit_ctx: Option<AuditContext>,
    /// Resource stats captured in wait() while cgroup still exists.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) final_stats: Option<ResourceUsage>,
}

impl Process {
    /// Get the PID of the sandboxed process.
    ///
    /// When PID namespace isolation is active, returns the target's
    /// host PID (not the wrapper/relay PID).
    #[cfg(not(windows))]
    pub fn pid(&self) -> u32 {
        #[cfg(target_os = "linux")]
        if let Some(tp) = self.target_pid {
            return tp;
        }
        match &self.child {
            ChildHandle::Managed(c) => c.id(),
            ChildHandle::Forked(pid) => *pid,
        }
    }

    /// Get the PID of the sandboxed process.
    #[cfg(windows)]
    pub fn pid(&self) -> u32 {
        self.process_id
    }

    /// Path to the process's temporary directory.
    pub fn tmp_dir(&self) -> &std::path::Path {
        &self.tmp_dir
    }

    /// Returns the PTY master FD, if TTY mode was requested.
    ///
    /// The returned `BorrowedFd` is lifetime-bound to this `Process`,
    /// preventing use-after-close.
    #[cfg(unix)]
    pub fn pty_master(&self) -> Option<std::os::unix::io::BorrowedFd<'_>> {
        self.pty_master.as_ref().map(|fd| fd.as_fd())
    }

    /// Send a signal to the sandboxed process.
    ///
    /// On Linux 5.3+, uses `pidfd_send_signal` for race-free delivery.
    /// Falls back to `kill()` on older kernels or non-Linux platforms,
    /// but only if `wait()` has not been called — after wait, the PID
    /// may be recycled and signaling is refused.
    #[cfg(unix)]
    pub fn signal(&self, sig: i32) -> crate::Result<()> {
        if self.waited {
            return Err(crate::Error::Process(
                "cannot signal after wait(): process already reaped".into(),
            ));
        }

        let pid = self.pid();
        if pid == 0 {
            return Err(crate::Error::Process("process already reaped".into()));
        }

        #[cfg(target_os = "linux")]
        if let Some(ref fd) = self.pidfd {
            use std::os::unix::io::AsRawFd;
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    sig,
                    std::ptr::null::<libc::c_void>(),
                    0u32,
                )
            };
            if ret != 0 {
                return Err(crate::Error::Syscall {
                    name: "pidfd_send_signal",
                    source: std::io::Error::last_os_error(),
                });
            }
            return Ok(());
        }

        let ret = unsafe { libc::kill(pid as libc::pid_t, sig) };
        if ret != 0 {
            return Err(crate::Error::Syscall {
                name: "kill",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    /// Wait for the process to exit and return the exit status.
    #[cfg(not(windows))]
    pub fn wait(&mut self) -> crate::Result<std::process::ExitStatus> {
        if self.waited {
            return Err(crate::Error::Process("process already waited".into()));
        }
        let pid = self.pid();

        // Capture the child's PID before wait() clears it. setsid()
        // in pre_exec makes child PID = PGID, so we can kill the
        // entire process group after the child exits to clean up
        // orphaned descendants that may hold pipe FDs open.
        // In supervisor mode the direct child is the supervisor,
        // which made the WRAPPER a group leader (setpgid) — the
        // group to sweep is the wrapper's, reported via the pid
        // report and stored in target_pid. Keying on the
        // supervisor's own pid would either be a no-op (the wrapper
        // left that group) or, after a pid recycle, kill an
        // unrelated process group.
        #[cfg(target_os = "linux")]
        let child_pgid: i32 = match self.target_pid {
            Some(p) if p > 1 => p as i32,
            _ => match &self.child {
                ChildHandle::Managed(c) => c.id() as i32,
                ChildHandle::Forked(p) => *p as i32,
            },
        };

        // macOS: wait for child to exit without reaping (WNOWAIT),
        // then cancel the memory monitor, join it, then reap.
        // This prevents PID recycling between reap and monitor stop.
        #[cfg(target_os = "macos")]
        if self.monitor_cancel.is_some() {
            let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
            loop {
                let ret = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid as libc::id_t,
                        &mut siginfo,
                        libc::WEXITED | libc::WNOWAIT,
                    )
                };
                if ret == 0 {
                    break;
                }
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
            }
            // Child is dead but still a zombie — safe to stop monitor.
            if let Some(cancel) = self.monitor_cancel.take() {
                cancel.store(true, std::sync::atomic::Ordering::Release);
            }
            if let Some(handle) = self.monitor_handle.take() {
                let _ = handle.join();
            }
        }

        let status = match &mut self.child {
            ChildHandle::Managed(c) => c
                .wait()
                .map_err(|e| crate::Error::Process(format!("wait: {e}")))?,
            ChildHandle::Forked(child_pid) => {
                use std::os::unix::process::ExitStatusExt;
                let mut wstatus: libc::c_int = 0;
                // SAFETY: child_pid is a valid PID from fork.
                let ret = unsafe { libc::waitpid(*child_pid as libc::pid_t, &mut wstatus, 0) };
                if ret < 0 {
                    return Err(crate::Error::Process(format!(
                        "waitpid: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                // Mark as reaped so Drop's *pid > 0 guard skips it,
                // preventing SIGKILL to a recycled PID.
                *child_pid = 0;
                std::process::ExitStatus::from_raw(wstatus)
            }
        };
        self.waited = true;

        // Kill orphaned descendants in the child's process group.
        // setsid() in pre_exec makes child PID = PGID. After the
        // child exits, orphaned grandchildren (e.g., a tracee whose
        // tracer was killed by SIGSYS) may hold inherited pipe FDs,
        // preventing EOF on the caller's pipes. In pidns mode,
        // namespace collapse handles this automatically.
        #[cfg(target_os = "linux")]
        if !self.pidns_active && child_pgid > 1 {
            unsafe { libc::kill(-child_pgid, libc::SIGKILL) };
        }

        // Read blocked-network audit data before emitting
        // ProcessExited, so NetworkBlocked events appear before
        // the exit event.
        self.read_dns_audit_pipe(pid);
        self.read_unotify_audit_pipe(pid);
        self.read_seatbelt_denials(pid);

        // Capture stats while cgroup still exists (before cleanup
        // destroys it). Eliminates the TOCTOU gap.
        self.final_stats = Some(self.resource_stats());
        let oom = self.oom_count();

        if let Some(ref ctx) = self.audit_ctx {
            use std::os::unix::process::ExitStatusExt;
            // Post-exit: can't abort, so discard mandatory emit errors.
            if let Err(e) = ctx.emit(AuditEvent::ProcessExited {
                timestamp: ctx.timestamp(),
                pid,
                exit_code: status.code(),
                signal: status.signal(),
                oom_kill_count: oom,
            }) {
                log::error!("audit emit failed: {e}");
            }

            if let Some(ref stats) = self.final_stats {
                if let Err(e) = ctx.emit(AuditEvent::ResourceUsage {
                    timestamp: ctx.timestamp(),
                    memory_current_bytes: stats.memory_current_bytes,
                    memory_peak_bytes: stats.memory_peak_bytes,
                    cpu_seconds: stats.cpu_usage_seconds,
                    pid_count: stats.pid_count,
                    io_read_bytes: stats.io_read_bytes,
                    io_write_bytes: stats.io_write_bytes,
                }) {
                    log::error!("audit emit failed: {e}");
                }
            }
        }

        Ok(status)
    }

    /// Wait for the process to exit and return the exit status.
    #[cfg(windows)]
    pub fn wait(&mut self) -> crate::Result<std::process::ExitStatus> {
        if self.waited {
            return Err(crate::Error::Process("process already waited".into()));
        }
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::process::ExitStatusExt;
        use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, INFINITE, WaitForSingleObject,
        };

        // SAFETY: process_handle is a valid process HANDLE.
        let ret =
            unsafe { WaitForSingleObject(self.process_handle.as_raw_handle() as HANDLE, INFINITE) };
        if ret == WAIT_FAILED {
            return Err(crate::Error::Process(format!(
                "WaitForSingleObject: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut exit_code: u32 = 1;
        // SAFETY: process_handle is valid, exit_code is a valid pointer.
        let ret = unsafe {
            GetExitCodeProcess(
                self.process_handle.as_raw_handle() as HANDLE,
                &mut exit_code,
            )
        };
        if ret == 0 {
            return Err(crate::Error::Process(format!(
                "GetExitCodeProcess: {}",
                std::io::Error::last_os_error()
            )));
        }

        let status = std::process::ExitStatus::from_raw(exit_code);
        let pid = self.process_id;

        if let Some(ref ctx) = self.audit_ctx {
            if let Err(e) = ctx.emit(AuditEvent::ProcessExited {
                timestamp: ctx.timestamp(),
                pid,
                exit_code: Some(exit_code as i32),
                signal: None,
                oom_kill_count: 0,
            }) {
                log::error!("audit emit failed: {e}");
            }
        }

        self.waited = true;
        Ok(status)
    }

    /// Read DNS audit events from the bridge child's pipe and emit
    /// `NetworkBlocked` events via the audit context.
    #[cfg(target_os = "linux")]
    #[cfg_attr(not(feature = "serde"), allow(unused_variables))]
    fn read_dns_audit_pipe(&mut self, pid: u32) {
        let owned_fd = match self.dns_audit_pipe.take() {
            Some(fd) => fd,
            None => return,
        };
        use std::os::unix::io::AsRawFd;
        let fd = owned_fd.as_raw_fd();

        // Poll with a 1-second timeout — the bridge should be dead
        // (pdeathsig) by now, but SIGKILL delivery is asynchronous.
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ret = loop {
            let ret = unsafe { libc::poll(&mut pfd, 1, 1000) };
            if ret >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break ret;
            }
        };
        if poll_ret == 0 {
            log::warn!("DNS audit pipe: timeout waiting for EOF (bridge may still be alive)");
            drop(owned_fd);
            return;
        }

        // Read all available data. Set O_NONBLOCK so we never block
        // waiting for the bridge child to die (SIGKILL is asynchronous).
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        const MAX_AUDIT_DRAIN: usize = 16 * 1024 * 1024;
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if data.len() >= MAX_AUDIT_DRAIN {
                log::warn!("dns audit pipe: truncating at {MAX_AUDIT_DRAIN} bytes");
                break;
            }
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if err.raw_os_error() == Some(libc::EAGAIN) {
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ret = unsafe { libc::poll(&mut pfd, 1, 1000) };
                    if ret <= 0 {
                        break;
                    }
                    continue;
                }
                break;
            }
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n as usize]);
        }
        drop(owned_fd);

        #[cfg(not(feature = "serde"))]
        if !data.is_empty() {
            log::warn!(
                "DNS audit: {} bytes discarded (compile with 'serde' feature to emit events)",
                data.len()
            );
        }

        #[cfg(feature = "serde")]
        if !data.is_empty() {
            let ctx = match self.audit_ctx {
                Some(ref ctx) => ctx,
                None => return,
            };
            let text = String::from_utf8_lossy(&data);
            for line in text.lines() {
                if line.is_empty() {
                    continue;
                }
                #[derive(serde::Deserialize)]
                struct DnsAuditLine {
                    domain: String,
                    qtype: String,
                }
                match serde_json::from_str::<DnsAuditLine>(line) {
                    Ok(entry) => {
                        if let Err(e) = ctx.emit(AuditEvent::NetworkBlocked {
                            timestamp: ctx.timestamp(),
                            pid,
                            destination: crate::audit::sanitize_audit_string(&entry.domain),
                            protocol: "dns".into(),
                            detail: Some(crate::audit::sanitize_audit_string(&entry.qtype)),
                        }) {
                            log::error!("audit emit failed: {e}");
                        }
                    }
                    Err(e) => {
                        log::debug!("DNS audit: skipping malformed line: {e}");
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[cfg_attr(windows, allow(dead_code))]
    fn read_dns_audit_pipe(&mut self, _pid: u32) {}

    #[cfg(target_os = "linux")]
    #[cfg_attr(not(feature = "serde"), allow(unused_variables))]
    fn read_unotify_audit_pipe(&mut self, pid: u32) {
        let owned_fd = match self.unotify_audit_pipe.take() {
            Some(fd) => fd,
            None => return,
        };

        let ctx = match self.audit_ctx.as_ref() {
            Some(ctx) => ctx,
            None => return,
        };

        // Same read pattern as read_dns_audit_pipe: poll + nonblock + drain.
        use std::os::unix::io::AsRawFd;
        let raw_fd = owned_fd.as_raw_fd();

        let mut pfd = libc::pollfd {
            fd: raw_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ret = loop {
            let ret = unsafe { libc::poll(&mut pfd, 1, 1000) };
            if ret >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break ret;
            }
        };
        if poll_ret <= 0 {
            return;
        }

        unsafe {
            let flags = libc::fcntl(raw_fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }

        const MAX_AUDIT_DRAIN: usize = 16 * 1024 * 1024;
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if data.len() >= MAX_AUDIT_DRAIN {
                log::warn!("unotify audit pipe: truncating at {MAX_AUDIT_DRAIN} bytes");
                break;
            }
            let n = unsafe { libc::read(raw_fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                data.extend_from_slice(&buf[..n as usize]);
            } else if n == 0 {
                break;
            } else {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    let mut pfd2 = libc::pollfd {
                        fd: raw_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ret = unsafe { libc::poll(&mut pfd2, 1, 1000) };
                    if ret <= 0 {
                        break;
                    }
                    continue;
                }
                break;
            }
        }
        drop(owned_fd);

        #[cfg(not(feature = "serde"))]
        if !data.is_empty() {
            log::warn!(
                "unotify audit: {} bytes discarded (compile with 'serde' feature to emit events)",
                data.len()
            );
        }

        #[cfg(feature = "serde")]
        if !data.is_empty() {
            let text = String::from_utf8_lossy(&data);
            for line in text.lines() {
                if line.is_empty() {
                    continue;
                }
                #[derive(serde::Deserialize)]
                struct UnotifyLine {
                    #[serde(rename = "type")]
                    event_type: String,
                    #[serde(default)]
                    pid: u32,
                    #[serde(default)]
                    path: Option<String>,
                    #[serde(default)]
                    flags: Option<u32>,
                    #[serde(default)]
                    is_write: Option<bool>,
                    #[serde(default)]
                    binary: Option<String>,
                    #[serde(default)]
                    dest: Option<String>,
                    #[serde(default)]
                    protocol: Option<String>,
                    #[serde(default)]
                    syscall: Option<String>,
                    #[serde(default)]
                    reason: Option<String>,
                    #[serde(default)]
                    count: Option<u64>,
                    #[serde(default)]
                    nr: Option<i64>,
                }
                match serde_json::from_str::<UnotifyLine>(line) {
                    Ok(entry) => {
                        let event_pid = if entry.pid > 0 { entry.pid } else { pid };
                        let result = match entry.event_type.as_str() {
                            "file_access" => ctx.emit(AuditEvent::FileAccess {
                                timestamp: ctx.timestamp(),
                                pid: event_pid,
                                path: crate::audit::sanitize_audit_string(
                                    &entry.path.unwrap_or_default(),
                                ),
                                flags: entry.flags.unwrap_or(0),
                                is_write: entry.is_write.unwrap_or(false),
                            }),
                            "process_spawn" => ctx.emit(AuditEvent::ProcessSpawn {
                                timestamp: ctx.timestamp(),
                                pid: event_pid,
                                binary: crate::audit::sanitize_audit_string(
                                    &entry.binary.unwrap_or_default(),
                                ),
                            }),
                            "network_blocked" => ctx.emit(AuditEvent::NetworkBlocked {
                                timestamp: ctx.timestamp(),
                                pid: event_pid,
                                destination: crate::audit::sanitize_audit_string(
                                    &entry.dest.unwrap_or_default(),
                                ),
                                protocol: crate::audit::sanitize_audit_string(
                                    &entry
                                        .syscall
                                        .clone()
                                        .or(entry.protocol)
                                        .unwrap_or_else(|| "tcp".into()),
                                ),
                                detail: Some("unotify".into()),
                            }),
                            "unix_socket_blocked" => ctx.emit(AuditEvent::UnixSocketBlocked {
                                timestamp: ctx.timestamp(),
                                pid: event_pid,
                                path: crate::audit::sanitize_audit_string(
                                    &entry.path.unwrap_or_default(),
                                ),
                                syscall: crate::audit::sanitize_audit_string(
                                    &entry.syscall.unwrap_or_else(|| "connect".into()),
                                ),
                                detail: entry
                                    .reason
                                    .map(|r| crate::audit::sanitize_audit_string(&r)),
                            }),
                            "inspection_failed" => ctx.emit(AuditEvent::InspectionFailed {
                                timestamp: ctx.timestamp(),
                                pid: event_pid,
                                syscall: entry
                                    .nr
                                    .map(|n| n.to_string())
                                    .or(entry.syscall)
                                    .unwrap_or_default(),
                            }),
                            "dropped" => {
                                if let Some(count) = entry.count {
                                    log::warn!("unotify: {count} audit events dropped (pipe full)");
                                }
                                Ok(())
                            }
                            _ => {
                                log::debug!("unotify: unknown event type: {}", entry.event_type);
                                Ok(())
                            }
                        };
                        if let Err(e) = result {
                            log::error!("unotify audit emit failed: {e}");
                        }
                    }
                    Err(e) => {
                        log::debug!("unotify audit: skipping malformed line: {e}");
                    }
                }
            }
        }
    }

    #[cfg(all(not(target_os = "linux"), not(windows)))]
    fn read_unotify_audit_pipe(&mut self, _pid: u32) {}

    #[cfg(target_os = "macos")]
    fn read_seatbelt_denials(&mut self, pid: u32) {
        let launch_time = match self.launch_timestamp.take() {
            Some(t) => t,
            None => return,
        };
        let ctx = match self.audit_ctx {
            Some(ref ctx) => ctx,
            None => return,
        };

        let fmt = |t: std::time::SystemTime| -> String {
            let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            let secs = d.as_secs();
            let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
            let ts = secs as libc::time_t;
            unsafe { libc::localtime_r(&ts, tm.as_mut_ptr()) };
            let tm = unsafe { tm.assume_init() };
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec,
            )
        };

        let start = fmt(launch_time);
        let end = fmt(std::time::SystemTime::now());
        let predicate = "subsystem == \"com.apple.sandbox\" \
             AND category == \"violation\" \
             AND eventMessage CONTAINS \"network\"";

        let mut child = match std::process::Command::new("log")
            .args([
                "show",
                "--start",
                &start,
                "--end",
                &end,
                "--style",
                "ndjson",
                "--predicate",
                predicate,
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                log::warn!("failed to spawn 'log show': {e}");
                return;
            }
        };

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let output = loop {
            match child.try_wait() {
                Ok(Some(_)) => break child.stdout.take(),
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        log::warn!("'log show' timed out (10s)");
                        break None;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(e) => {
                    log::warn!("'log show' wait failed: {e}");
                    break None;
                }
            }
        };

        if let Some(stdout) = output {
            let reader = std::io::BufReader::new(stdout);
            use std::io::BufRead;
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                if line.is_empty() {
                    continue;
                }
                let pid_field = format!("\"processID\":{pid},");
                let pid_field_end = format!("\"processID\":{pid}}}");
                let pgid_field = format!("\"processGroupID\":{pid},");
                let pgid_field_end = format!("\"processGroupID\":{pid}}}");
                if !line.contains(&pid_field)
                    && !line.contains(&pid_field_end)
                    && !line.contains(&pgid_field)
                    && !line.contains(&pgid_field_end)
                {
                    continue;
                }
                let (destination, protocol) = match extract_seatbelt_destination(&line) {
                    Some((dest, proto)) => (dest, proto),
                    None => ("<unknown>".into(), "network".into()),
                };
                if let Err(e) = ctx.emit(AuditEvent::NetworkBlocked {
                    timestamp: ctx.timestamp(),
                    pid,
                    destination: crate::audit::sanitize_audit_string(&destination),
                    protocol: crate::audit::sanitize_audit_string(&protocol),
                    detail: Some("seatbelt-deny".into()),
                }) {
                    log::error!("audit emit failed: {e}");
                }
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[cfg_attr(windows, allow(dead_code))]
    fn read_seatbelt_denials(&mut self, _pid: u32) {}

    /// Read resource usage from the agent's cgroup.
    ///
    /// Must be called before `cleanup()` which destroys the cgroup.
    /// Returns zero values if cgroups are unavailable.
    pub fn resource_stats(&self) -> ResourceUsage {
        #[cfg(target_os = "linux")]
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &self.cgroup_path) {
            return mgr.read_stats(path);
        }
        ResourceUsage::default()
    }

    /// Read the OOM kill count from the agent's cgroup.
    ///
    /// Must be called before `cleanup()` which destroys the cgroup.
    /// Returns 0 if cgroups are unavailable.
    pub fn oom_count(&self) -> u32 {
        #[cfg(target_os = "linux")]
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &self.cgroup_path) {
            return mgr.read_oom_events(path);
        }
        0
    }

    /// Clean up the sandbox temp directory and cgroup.
    ///
    /// Must only be called after `wait()` returns. Uses `take()` on
    /// cgroup/Windows fields so Drop sees None and does not double-
    /// cleanup. For tmpdir, Drop uses an `exists()` guard instead
    /// (tmpdir stays PathBuf to preserve the public API).
    #[allow(unused_mut)]
    pub fn cleanup(mut self) {
        #[allow(unused_mut)]
        let mut cgroup_destroyed = false;
        #[cfg(target_os = "linux")]
        {
            let mgr = self.cgroup_mgr.take();
            let path = self.cgroup_path.take();
            if let (Some(mgr), Some(path)) = (&mgr, &path) {
                cgroup_destroyed = mgr.destroy(path).is_ok();
            }
        }

        #[cfg(windows)]
        let mut dacls_restored = true;
        #[cfg(windows)]
        let mut container_deleted = false;
        #[cfg(windows)]
        {
            let saved_dacls = std::mem::take(&mut self.saved_dacls);
            for saved in &saved_dacls {
                if let Err(e) = crate::platform::windows::restore_dacl(saved) {
                    log::warn!("failed to restore DACL: {e}");
                    dacls_restored = false;
                }
            }
            if let Some(name) = self.container_name.take() {
                container_deleted = crate::platform::windows::delete_app_container(&name).is_ok();
            }
        }

        let tmpdir_removed = if self.tmp_dir.exists() {
            std::fs::remove_dir_all(&self.tmp_dir).is_ok()
        } else {
            true
        };

        if let Some(ref ctx) = self.audit_ctx {
            if let Err(e) = ctx.emit(AuditEvent::SandboxCleanup {
                timestamp: ctx.timestamp(),
                cgroup_destroyed,
                tmpdir_removed,
                #[cfg(windows)]
                dacls_restored: Some(dacls_restored),
                #[cfg(not(windows))]
                dacls_restored: None,
                #[cfg(windows)]
                container_deleted: Some(container_deleted),
                #[cfg(not(windows))]
                container_deleted: None,
            }) {
                log::error!("audit emit failed: {e}");
            }
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // macOS: cancel the memory monitor before killing/reaping
        // the child to prevent PID recycling races.
        #[cfg(target_os = "macos")]
        {
            if let Some(cancel) = self.monitor_cancel.take() {
                cancel.store(true, std::sync::atomic::Ordering::Release);
            }
            if let Some(handle) = self.monitor_handle.take() {
                let _ = handle.join();
            }
        }

        // Capture the PGID before killing/reaping the child (same
        // supervisor-mode re-keying as in wait(): the wrapper's
        // group, not the supervisor's).
        #[cfg(target_os = "linux")]
        let child_pgid: i32 = match self.target_pid {
            Some(p) if p > 1 => p as i32,
            _ => match &self.child {
                ChildHandle::Managed(c) => c.id() as i32,
                ChildHandle::Forked(p) => *p as i32,
            },
        };

        // Kill the child process first to ensure resources can be
        // reclaimed. Without this, cgroups can't be destroyed while
        // occupied, and a live process would run unsupervised after
        // its containment is removed.
        #[cfg(not(windows))]
        #[allow(clippy::collapsible_match)]
        match &mut self.child {
            ChildHandle::Managed(c) => {
                if !self.waited {
                    // pidfd targets the sandboxed process (target in
                    // pidns); c.wait() waits for the wrapper/relay
                    // which exits after the target.
                    #[cfg(target_os = "linux")]
                    if let Some(ref fd) = self.pidfd {
                        use std::os::unix::io::AsRawFd;
                        let _ = unsafe {
                            libc::syscall(
                                libc::SYS_pidfd_send_signal,
                                fd.as_raw_fd(),
                                libc::SIGKILL,
                                std::ptr::null::<libc::c_void>(),
                                0u32,
                            )
                        };
                    } else {
                        let _ = c.kill();
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = c.kill();
                    }
                    let _ = c.wait();
                }
            }
            ChildHandle::Forked(pid) if *pid > 0 => {
                #[cfg(target_os = "linux")]
                if let Some(ref fd) = self.pidfd {
                    use std::os::unix::io::AsRawFd;
                    let _ = unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            fd.as_raw_fd(),
                            libc::SIGKILL,
                            std::ptr::null::<libc::c_void>(),
                            0u32,
                        )
                    };
                } else {
                    unsafe { libc::kill(*pid as libc::pid_t, libc::SIGKILL) };
                }
                #[cfg(not(target_os = "linux"))]
                unsafe {
                    libc::kill(*pid as libc::pid_t, libc::SIGKILL);
                }
                unsafe {
                    libc::waitpid(*pid as libc::pid_t, std::ptr::null_mut(), 0);
                }
            }
            _ => {}
        }

        // Kill orphaned descendants (same rationale as in wait()).
        // Only when wait() hasn't already done this — otherwise the
        // PGID may have been recycled.
        #[cfg(target_os = "linux")]
        if !self.waited && !self.pidns_active && child_pgid > 1 {
            unsafe { libc::kill(-child_pgid, libc::SIGKILL) };
        }

        #[cfg(target_os = "linux")]
        drop(self.dns_audit_pipe.take());
        #[cfg(target_os = "linux")]
        drop(self.unotify_audit_pipe.take());

        #[cfg(target_os = "linux")]
        crate::bridge::cleanup_connect_proxy(
            self.connect_proxy_pid,
            self.connect_proxy_pidfd,
            &self.connect_proxy_socket,
        );

        #[cfg(target_os = "linux")]
        if let (Some(mgr), Some(path)) = (&self.cgroup_mgr, &self.cgroup_path) {
            let _ = mgr.destroy(path);
        }

        #[cfg(windows)]
        {
            for saved in &self.saved_dacls {
                let _ = crate::platform::windows::restore_dacl(saved);
            }
            if let Some(ref name) = self.container_name {
                let _ = crate::platform::windows::delete_app_container(name);
            }
        }

        if self.tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.tmp_dir);
        }
    }
}

/// Extract a network destination from a Seatbelt denial log line.
#[cfg(any(target_os = "macos", test))]
fn extract_seatbelt_destination(ndjson_line: &str) -> Option<(String, String)> {
    let msg_start = ndjson_line.find("\"eventMessage\"")?;
    let msg_area = &ndjson_line[msg_start..];

    // Try unescaped addr "..." first, then JSON-escaped addr \"...\"
    if let Some(addr_pos) = msg_area.find("addr \"") {
        let start = addr_pos + 6;
        let rest = &msg_area[start..];
        if let Some(end) = rest.find('"') {
            return Some((rest[..end].to_string(), "network".into()));
        }
    }
    if let Some(addr_pos) = msg_area.find("addr \\\"") {
        let start = addr_pos + 7;
        let rest = &msg_area[start..];
        if let Some(end) = rest.find("\\\"") {
            return Some((rest[..end].to_string(), "network".into()));
        }
    }

    for (proto_str, proto_name) in [("remote tcp ", "tcp"), ("remote udp ", "udp")] {
        if let Some(pos) = msg_area.find(proto_str) {
            let start = pos + proto_str.len();
            let rest = &msg_area[start..];
            let end = rest.find(['"', ')', ',']).unwrap_or(rest.len());
            let addr = rest[..end].trim();
            if !addr.is_empty() {
                return Some((addr.to_string(), proto_name.into()));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn process_drop_cleans_tmpdir() {
        let dir = crate::env::make_tmp_dir("drop-test").unwrap();
        assert!(dir.exists());
        {
            let child = std::process::Command::new("true")
                .spawn()
                .expect("failed to spawn true");
            let _process = Process {
                child: ChildHandle::Managed(child),
                tmp_dir: dir.clone(),
                #[cfg(target_os = "linux")]
                cgroup_path: None,
                #[cfg(target_os = "linux")]
                cgroup_mgr: None,
                #[cfg(target_os = "linux")]
                dns_audit_pipe: None,
                #[cfg(target_os = "linux")]
                unotify_audit_pipe: None,
                #[cfg(target_os = "linux")]
                pidfd: None,
                #[cfg(target_os = "linux")]
                target_pid: None,
                #[cfg(target_os = "linux")]
                pidns_active: false,
                waited: false,
                #[cfg(target_os = "linux")]
                connect_proxy_pid: None,
                #[cfg(target_os = "linux")]
                connect_proxy_pidfd: None,
                #[cfg(target_os = "linux")]
                connect_proxy_socket: None,
                #[cfg(target_os = "macos")]
                launch_timestamp: None,
                #[cfg(target_os = "macos")]
                monitor_cancel: None,
                #[cfg(target_os = "macos")]
                monitor_handle: None,
                #[cfg(all(target_os = "linux", feature = "microvm"))]
                passt: None,
                pty_master: None,
                audit_ctx: None,
                final_stats: None,
            };
        }
        assert!(!dir.exists(), "Drop should have removed the tmpdir");
    }

    #[test]
    fn seatbelt_extract_addr_escaped() {
        // macOS log show --style ndjson escapes quotes inside
        // eventMessage as \". Test the escaped addr pattern.
        let line = "{\"processID\":42,\"eventMessage\":\"deny(1) network-outbound addr \\\"1.2.3.4:443\\\"\"}";
        let (dest, proto) = extract_seatbelt_destination(line).unwrap();
        assert_eq!(dest, "1.2.3.4:443");
        assert_eq!(proto, "network");
    }

    #[test]
    fn seatbelt_extract_remote_tcp() {
        let line =
            r#"{"processID":42,"eventMessage":"deny(1) network-outbound remote tcp 10.0.0.1:80"}"#;
        let (dest, proto) = extract_seatbelt_destination(line).unwrap();
        assert_eq!(dest, "10.0.0.1:80");
        assert_eq!(proto, "tcp");
    }

    #[test]
    fn seatbelt_extract_remote_udp() {
        let line =
            r#"{"processID":42,"eventMessage":"deny(1) network-outbound remote udp 8.8.8.8:53"}"#;
        let (dest, proto) = extract_seatbelt_destination(line).unwrap();
        assert_eq!(dest, "8.8.8.8:53");
        assert_eq!(proto, "udp");
    }

    #[test]
    fn seatbelt_extract_no_match() {
        let line = r#"{"processID":42,"eventMessage":"deny(1) file-read-data /etc/passwd"}"#;
        assert!(extract_seatbelt_destination(line).is_none());
    }

    #[test]
    fn seatbelt_extract_no_event_message() {
        let line = r#"{"processID":42,"subsystem":"sandbox"}"#;
        assert!(extract_seatbelt_destination(line).is_none());
    }

    #[cfg(all(target_os = "linux", feature = "serde"))]
    #[test]
    fn dns_audit_pipe_emits_network_blocked() {
        use std::sync::{Arc, Mutex};

        struct VecSink(Mutex<Vec<crate::audit::AuditEvent>>);
        impl crate::audit::AuditSink for VecSink {
            fn emit(&self, event: crate::audit::AuditEvent) {
                self.0.lock().unwrap().push(event);
            }
        }

        let mut pipe_fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let pipe_read = pipe_fds[0];
        let pipe_write = pipe_fds[1];

        let ndjson = b"{\"domain\":\"evil.example.com\",\"qtype\":\"A\"}\n\
                       {\"domain\":\"bad.test\",\"qtype\":\"AAAA\"}\n";
        unsafe {
            libc::write(pipe_write, ndjson.as_ptr().cast(), ndjson.len());
            libc::close(pipe_write);
        }

        let vec_sink = Arc::new(VecSink(Mutex::new(Vec::new())));
        let sink: Arc<dyn crate::audit::AuditSink> = Arc::clone(&vec_sink) as _;
        let ctx = crate::audit::AuditContext::new(sink, crate::audit::AuditVerbosity::Standard);

        let dir = crate::env::make_tmp_dir("dns-audit-test").unwrap();
        let child = std::process::Command::new("true")
            .spawn()
            .expect("failed to spawn true");
        let mut process = Process {
            child: ChildHandle::Managed(child),
            tmp_dir: dir,
            cgroup_path: None,
            cgroup_mgr: None,
            dns_audit_pipe: Some(unsafe { std::os::unix::io::OwnedFd::from_raw_fd(pipe_read) }),
            unotify_audit_pipe: None,
            pidfd: None,
            target_pid: None,
            pidns_active: false,
            waited: false,
            #[cfg(target_os = "macos")]
            launch_timestamp: None,
            #[cfg(target_os = "macos")]
            monitor_cancel: None,
            #[cfg(target_os = "macos")]
            monitor_handle: None,
            #[cfg(all(target_os = "linux", feature = "microvm"))]
            passt: None,
            pty_master: None,
            audit_ctx: Some(ctx),
            final_stats: None,
        };

        process.read_dns_audit_pipe(42);

        let captured = vec_sink.0.lock().unwrap();
        let blocked: Vec<_> = captured
            .iter()
            .filter(|e| matches!(e, crate::audit::AuditEvent::NetworkBlocked { .. }))
            .collect();
        assert_eq!(blocked.len(), 2, "should emit 2 NetworkBlocked events");

        if let crate::audit::AuditEvent::NetworkBlocked {
            destination,
            protocol,
            detail,
            ..
        } = &blocked[0]
        {
            assert_eq!(destination, "evil.example.com");
            assert_eq!(protocol, "dns");
            assert_eq!(detail.as_deref(), Some("A"));
        } else {
            panic!("expected NetworkBlocked");
        }

        if let crate::audit::AuditEvent::NetworkBlocked {
            destination,
            detail,
            ..
        } = &blocked[1]
        {
            assert_eq!(destination, "bad.test");
            assert_eq!(detail.as_deref(), Some("AAAA"));
        } else {
            panic!("expected NetworkBlocked");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn signal_after_wait_without_pidfd_returns_error() {
        let child = std::process::Command::new("true")
            .spawn()
            .expect("failed to spawn true");
        let mut process = Process {
            child: ChildHandle::Managed(child),
            tmp_dir: crate::env::make_tmp_dir("signal-test").unwrap(),
            #[cfg(target_os = "linux")]
            cgroup_path: None,
            #[cfg(target_os = "linux")]
            cgroup_mgr: None,
            #[cfg(target_os = "linux")]
            dns_audit_pipe: None,
            #[cfg(target_os = "linux")]
            unotify_audit_pipe: None,
            #[cfg(target_os = "linux")]
            pidfd: None,
            #[cfg(target_os = "linux")]
            target_pid: None,
            #[cfg(target_os = "linux")]
            pidns_active: false,
            waited: false,
            #[cfg(target_os = "linux")]
            connect_proxy_pid: None,
            #[cfg(target_os = "linux")]
            connect_proxy_pidfd: None,
            #[cfg(target_os = "linux")]
            connect_proxy_socket: None,
            #[cfg(target_os = "macos")]
            launch_timestamp: None,
            #[cfg(target_os = "macos")]
            monitor_cancel: None,
            #[cfg(target_os = "macos")]
            monitor_handle: None,
            #[cfg(all(target_os = "linux", feature = "microvm"))]
            passt: None,
            pty_master: None,
            audit_ctx: None,
            final_stats: None,
        };
        let _ = process.wait();
        let result = process.signal(libc::SIGTERM);
        assert!(
            result.is_err(),
            "signal after wait without pidfd should fail"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("cannot signal after wait"),
            "expected 'cannot signal after wait', got: {err}"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn double_wait_returns_error() {
        let child = std::process::Command::new("true")
            .spawn()
            .expect("failed to spawn true");
        let mut process = Process {
            child: ChildHandle::Managed(child),
            tmp_dir: crate::env::make_tmp_dir("double-wait-test").unwrap(),
            #[cfg(target_os = "linux")]
            cgroup_path: None,
            #[cfg(target_os = "linux")]
            cgroup_mgr: None,
            #[cfg(target_os = "linux")]
            dns_audit_pipe: None,
            #[cfg(target_os = "linux")]
            unotify_audit_pipe: None,
            #[cfg(target_os = "linux")]
            pidfd: None,
            #[cfg(target_os = "linux")]
            target_pid: None,
            #[cfg(target_os = "linux")]
            pidns_active: false,
            waited: false,
            #[cfg(target_os = "linux")]
            connect_proxy_pid: None,
            #[cfg(target_os = "linux")]
            connect_proxy_pidfd: None,
            #[cfg(target_os = "linux")]
            connect_proxy_socket: None,
            #[cfg(target_os = "macos")]
            launch_timestamp: None,
            #[cfg(target_os = "macos")]
            monitor_cancel: None,
            #[cfg(target_os = "macos")]
            monitor_handle: None,
            #[cfg(all(target_os = "linux", feature = "microvm"))]
            passt: None,
            pty_master: None,
            audit_ctx: None,
            final_stats: None,
        };
        assert!(process.wait().is_ok());
        let result = process.wait();
        assert!(result.is_err(), "double wait should fail");
        assert!(
            result.unwrap_err().to_string().contains("already waited"),
            "expected 'already waited' error"
        );
    }
}
