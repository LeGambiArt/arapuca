//! C FFI layer for arapuca.
//!
//! Provides a C-compatible API using opaque types, null-checked pointers,
//! and thread-local error strings.
//!
//! # Safety Contract
//!
//! 1. All pointer params are null-checked before dereference.
//! 2. `_free()` functions use `Option::take()` — double-free is a safe no-op.
//! 3. Opaque types are `!Send` — callers must not share across threads.
//! 4. All `const char*` params are validated (null, UTF-8, length).
//! 5. `arapuca_last_error()` returns a thread-local pointer valid until
//!    the next arapuca call on the same thread.
//! 6. Strings returned by arapuca MUST be freed with `arapuca_free_string()`,
//!    NOT with `free()` — different allocators.

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::path::PathBuf;

use crate::platform::Sandbox;
use crate::{Config, Profile};

/// Maximum length for string inputs via FFI (4 KiB).
const MAX_STRING_LEN: usize = 4096;

// ─── Thread-local error storage ─────────────────────────────────────

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_error(msg: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = CString::new(msg).ok();
    });
}

fn clear_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

// ─── Opaque types ───────────────────────────────────────────────────

/// Opaque profile builder.
pub struct ArapucaProfile {
    inner: Option<Profile>,
}

/// Opaque sandbox handle (platform-specific, type-erased).
pub struct ArapucaSandbox {
    inner: Option<Box<dyn Sandbox>>,
}

/// Opaque launch config.
pub struct ArapucaConfig {
    inner: Option<Config>,
}

/// Opaque process handle.
pub struct ArapucaProcess {
    inner: Option<crate::Process>,
}

// ─── Non-opaque types ───────────────────────────────────────────────

/// Resource usage statistics from cgroups v2.
#[repr(C)]
pub struct ArapucaResourceUsage {
    pub memory_current_bytes: i64,
    pub memory_peak_bytes: i64,
    pub cpu_usage_seconds: f64,
    pub pid_count: i64,
    pub io_read_bytes: i64,
    pub io_write_bytes: i64,
}

// ─── Profile API ────────────────────────────────────────────────────

/// Create a new profile builder.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_profile_new() -> *mut ArapucaProfile {
    clear_error();
    Box::into_raw(Box::new(ArapucaProfile {
        inner: Some(Profile::default()),
    }))
}

/// Add a read-only path to the profile. Returns 0 on success, -1 on error.
///
/// # Safety
/// `profile` and `path` must be valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_add_read_path(
    profile: *mut ArapucaProfile,
    path: *const c_char,
) -> i32 {
    clear_error();
    let Some(profile) = (unsafe { profile.as_mut() }) else {
        set_error("null profile pointer");
        return -1;
    };
    let Some(inner) = profile.inner.as_mut() else {
        set_error("profile already freed");
        return -1;
    };
    let path = match unsafe { validate_cstr(path) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return -1;
        }
    };
    inner.read_paths.push(PathBuf::from(path));
    0
}

/// Add a read-write path to the profile. Returns 0 on success, -1 on error.
///
/// # Safety
/// `profile` and `path` must be valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_add_write_path(
    profile: *mut ArapucaProfile,
    path: *const c_char,
) -> i32 {
    clear_error();
    let Some(profile) = (unsafe { profile.as_mut() }) else {
        set_error("null profile pointer");
        return -1;
    };
    let Some(inner) = profile.inner.as_mut() else {
        set_error("profile already freed");
        return -1;
    };
    let path = match unsafe { validate_cstr(path) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return -1;
        }
    };
    inner.write_paths.push(PathBuf::from(path));
    0
}

/// Set memory limit in MB. Enforced via cgroups v2 `memory.max`
/// on Linux (through the launch path) and RSS polling on macOS.
/// Does NOT set RLIMIT_AS, which would break Go/JVM/.NET runtimes.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_memory_mb(profile: *mut ArapucaProfile, mb: u64) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.max_memory_mb = mb;
        }
    }
}

/// Set CPU percentage limit.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_cpu_pct(profile: *mut ArapucaProfile, pct: u32) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.max_cpu_pct = pct;
        }
    }
}

/// Set maximum PIDs. Enforced via cgroups v2 `pids.max` on Linux
/// (through the launch path). Does NOT set RLIMIT_NPROC, which is
/// a per-UID system-wide limit that breaks sandboxed workloads.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_max_pids(profile: *mut ArapucaProfile, pids: u32) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.max_pids = pids;
        }
    }
}

/// Set maximum file size in MB (RLIMIT_FSIZE).
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_max_file_size_mb(
    profile: *mut ArapucaProfile,
    mb: u64,
) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.max_file_size_mb = mb;
        }
    }
}

/// Set maximum open file descriptors (RLIMIT_NOFILE).
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_max_open_files(profile: *mut ArapucaProfile, n: u64) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.max_open_files = n;
        }
    }
}

/// Enable/disable exec permission for sandboxed processes.
///
/// When enabled, read paths gain the Landlock `Execute` access right,
/// allowing `execve` on any binary reachable through them. Write
/// paths also gain Execute (they receive full access). When disabled
/// (the default), only the target binary and the ELF interpreter are
/// executable.
///
/// Scripts that use a shebang (e.g. `#!/usr/bin/env python3`) require
/// `allow_exec = true` because the kernel's script interpreter
/// resolution needs Execute on the interpreter binary, not just the
/// script itself.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_allow_exec(
    profile: *mut ArapucaProfile,
    enabled: bool,
) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.allow_exec = enabled;
        }
    }
}

/// Set cgroup enforcement policy.
///
/// When `best_effort` is true, the sandbox uses whatever cgroup
/// controllers are delegated and skips the rest with a warning.
/// When false (default), missing cgroup controllers cause a hard failure.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_cgroup_best_effort(
    profile: *mut ArapucaProfile,
    best_effort: bool,
) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.cgroup_policy = if best_effort {
                crate::CgroupPolicy::BestEffort
            } else {
                crate::CgroupPolicy::Required
            };
        }
    }
}

/// Set a hard CPU-time cap in seconds via RLIMIT_CPU.
///
/// Kills the process with SIGXCPU after `seconds` of cumulative CPU
/// time. Independent of `max_cpu_pct` (proportional scheduling).
/// Set to 0 to disable (default).
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_cpu_timeout(
    profile: *mut ArapucaProfile,
    seconds: u64,
) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.cpu_timeout_secs = seconds;
        }
    }
}

/// Enable/disable network namespace isolation.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_netns(profile: *mut ArapucaProfile, enabled: bool) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.use_netns = enabled;
        }
    }
}

/// Allow the sandboxed process to bind and accept TCP connections.
///
/// On macOS, Seatbelt cannot guarantee that listeners are confined to
/// loopback; enable only for trusted applications. On Linux, listeners are
/// confined to the isolated network namespace.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_network_listeners(
    profile: *mut ArapucaProfile,
    enabled: bool,
) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.allow_network_listeners = enabled;
        }
    }
}

/// Set the seccomp profile for the sandboxed process.
///
/// `profile_str` must be a null-terminated string: `"strict"` (default)
/// or `"baseline"`. Strict blocks AF_INET/AF_INET6, memfd_create,
/// io_uring, and other advanced syscalls. Baseline blocks only
/// sandbox-escape syscalls and is designed for trusted-but-isolated
/// applications such as Claude Code that need full POSIX syscall
/// access. Returns 0 on success, -1 if the profile string is invalid.
///
/// # Safety
/// `profile` and `profile_str` must be valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_seccomp(
    profile: *mut ArapucaProfile,
    profile_str: *const c_char,
) -> i32 {
    clear_error();
    let Some(profile) = (unsafe { profile.as_mut() }) else {
        set_error("null profile pointer");
        return -1;
    };
    let Some(inner) = profile.inner.as_mut() else {
        set_error("profile already freed");
        return -1;
    };
    let s = match unsafe { validate_cstr(profile_str) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return -1;
        }
    };
    match s.as_str() {
        "strict" => inner.seccomp_profile = crate::SeccompProfile::Strict,
        "baseline" => inner.seccomp_profile = crate::SeccompProfile::Baseline,
        _ => {
            set_error("invalid seccomp profile: expected \"strict\" or \"baseline\"");
            return -1;
        }
    }
    0
}

/// Enable or disable PID namespace isolation.
///
/// When enabled, the sandboxed process runs in an isolated PID
/// namespace where it cannot see or signal host processes.
/// Requires a user namespace (provided by netns or added
/// automatically).
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_pidns(profile: *mut ArapucaProfile, enabled: bool) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.use_pidns = enabled;
        }
    }
}

/// Enable/disable Windows LPAC (Less Privileged AppContainer).
///
/// Off by default. AppContainer confinement is always engaged on
/// Windows regardless of this setting; LPAC additionally strips the
/// implicit "ALL APPLICATION PACKAGES" SID, which most non-Microsoft-
/// signed binaries depend on for registry/DLL access and will fail to
/// launch without. No effect on non-Windows platforms.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_lpac(profile: *mut ArapucaProfile, enabled: bool) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.lpac = enabled;
        }
    }
}

/// Enable DNS query capture inside the network namespace.
///
/// When enabled alongside netns, the bridge child intercepts DNS
/// queries and emits `NetworkBlocked` audit events. Requires the
/// `serde` feature and the wrapper binary with filesystem paths.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_dns_capture(
    profile: *mut ArapucaProfile,
    enabled: bool,
) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.dns_capture = enabled;
        }
    }
}

/// Set micro-VM isolation on a profile with a distro image source.
///
/// After this call, launching with this profile creates a VM instead
/// of a process-level sandbox. Requires the `microvm` feature.
///
/// # Safety
/// `profile` and `distro`/`version` must be valid pointers.
#[cfg(feature = "microvm")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_isolation_microvm(
    profile: *mut ArapucaProfile,
    distro: *const c_char,
    version: *const c_char,
    cpus: u32,
    mem_mb: u32,
) -> i32 {
    clear_error();
    let Some(profile) = (unsafe { profile.as_mut() }) else {
        set_error("null profile pointer");
        return -1;
    };
    let Some(inner) = profile.inner.as_mut() else {
        set_error("profile already freed");
        return -1;
    };
    let distro = match unsafe { validate_cstr(distro) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return -1;
        }
    };
    let version = match unsafe { validate_cstr(version) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return -1;
        }
    };
    if cpus == 0 || mem_mb == 0 {
        set_error("cpus and mem_mb must be non-zero");
        return -1;
    }
    inner.isolation = crate::Isolation::MicroVm(crate::MicroVmConfig {
        image: crate::ImageSource::Distro {
            name: distro,
            version,
        },
        cpus,
        mem_mb,
        write_files: vec![],
    });
    0
}

/// Set micro-VM isolation on a profile with an explicit image path.
///
/// # Safety
/// `profile` and `image_path` must be valid pointers.
#[cfg(feature = "microvm")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_isolation_microvm_path(
    profile: *mut ArapucaProfile,
    image_path: *const c_char,
    cpus: u32,
    mem_mb: u32,
) -> i32 {
    clear_error();
    let Some(profile) = (unsafe { profile.as_mut() }) else {
        set_error("null profile pointer");
        return -1;
    };
    let Some(inner) = profile.inner.as_mut() else {
        set_error("profile already freed");
        return -1;
    };
    let path = match unsafe { validate_cstr(image_path) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return -1;
        }
    };
    if cpus == 0 || mem_mb == 0 {
        set_error("cpus and mem_mb must be non-zero");
        return -1;
    }
    inner.isolation = crate::Isolation::MicroVm(crate::MicroVmConfig {
        image: crate::ImageSource::Path(PathBuf::from(path)),
        cpus,
        mem_mb,
        write_files: vec![],
    });
    0
}

/// Free a profile. Safe to call with NULL.
///
/// # Safety
/// `profile` must be NULL or a valid pointer from `arapuca_profile_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_free(profile: *mut ArapucaProfile) {
    if !profile.is_null() {
        let mut p = unsafe { Box::from_raw(profile) };
        p.inner.take();
    }
}

// ─── Sandbox API ────────────────────────────────────────────────────

/// Create a new sandbox for the current platform.
///
/// Returns NULL on error (check `arapuca_last_error()`).
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_sandbox_new() -> *mut ArapucaSandbox {
    clear_error();
    match crate::platform::new_boxed() {
        Ok(sb) => Box::into_raw(Box::new(ArapucaSandbox { inner: Some(sb) })),
        Err(e) => {
            set_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Check whether cgroups v2 resource limits are available.
///
/// # Safety
/// `sb` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_sandbox_cgroups_available(sb: *const ArapucaSandbox) -> bool {
    let Some(sb) = (unsafe { sb.as_ref() }) else {
        return false;
    };
    sb.inner.as_ref().is_some_and(|s| s.cgroups_available())
}

/// Free a sandbox handle. Safe to call with NULL.
///
/// # Safety
/// `sb` must be NULL or a valid pointer from `arapuca_sandbox_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_sandbox_free(sb: *mut ArapucaSandbox) {
    if !sb.is_null() {
        let mut s = unsafe { Box::from_raw(sb) };
        s.inner.take();
    }
}

// ─── Config API ─────────────────────────────────────────────────────

/// Create a new launch config.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_config_new() -> *mut ArapucaConfig {
    clear_error();
    Box::into_raw(Box::new(ArapucaConfig {
        inner: Some(Config {
            profile: Profile::default(),
            socket_dir: PathBuf::new(),
            task_id: String::new(),
            phase: String::new(),
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
            #[cfg(target_os = "linux")]
            allowed_hosts: Vec::new(),
            env: Vec::new(),
            audit_sink: None,
            audit_verbosity: crate::audit::AuditVerbosity::Standard,
            audit_principal: None,
            audit_correlation_id: None,
        }),
    }))
}

/// Set the profile on a config (clones the profile).
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_profile(
    cfg: *mut ArapucaConfig,
    profile: *const ArapucaProfile,
) -> i32 {
    clear_error();
    let (Some(cfg), Some(profile)) = (unsafe { cfg.as_mut() }, unsafe { profile.as_ref() }) else {
        set_error("null pointer");
        return -1;
    };
    let (Some(cfg_inner), Some(profile_inner)) = (cfg.inner.as_mut(), profile.inner.as_ref())
    else {
        set_error("already freed");
        return -1;
    };
    cfg_inner.profile = profile_inner.clone();
    0
}

/// Set the task ID on a config.
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_task_id(
    cfg: *mut ArapucaConfig,
    task_id: *const c_char,
) -> i32 {
    unsafe { set_config_string(cfg, task_id, |c, s| c.task_id = s) }
}

/// Set the phase on a config.
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_phase(
    cfg: *mut ArapucaConfig,
    phase: *const c_char,
) -> i32 {
    unsafe { set_config_string(cfg, phase, |c, s| c.phase = s) }
}

/// Set the socket directory on a config.
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_socket_dir(
    cfg: *mut ArapucaConfig,
    dir: *const c_char,
) -> i32 {
    unsafe { set_config_string(cfg, dir, |c, s| c.socket_dir = PathBuf::from(s)) }
}

/// Set the working directory on a config.
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_work_dir(
    cfg: *mut ArapucaConfig,
    dir: *const c_char,
) -> i32 {
    unsafe { set_config_string(cfg, dir, |c, s| c.work_dir = Some(PathBuf::from(s))) }
}

/// Helper to set an FD field on a config with validation.
///
/// FDs 0, 1, 2 are valid — `F_DUPFD_CLOEXEC` creates a new FD without
/// disturbing the parent's original stdio descriptors.
#[cfg(unix)]
fn set_config_fd(cfg: *mut ArapucaConfig, fd: i32, setter: impl FnOnce(&mut Config, i32)) -> i32 {
    clear_error();
    let Some(cfg) = (unsafe { cfg.as_mut() }) else {
        set_error("null config pointer");
        return -1;
    };
    let Some(inner) = cfg.inner.as_mut() else {
        set_error("config already freed");
        return -1;
    };
    if fd < 0 {
        set_error("invalid fd: must be >= 0");
        return -1;
    }
    setter(inner, fd);
    0
}

/// Set stdin FD on a config. Returns 0 on success, -1 on error.
///
/// # Safety
/// `cfg` must be a valid pointer.
#[cfg(unix)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_stdin_fd(cfg: *mut ArapucaConfig, fd: i32) -> i32 {
    set_config_fd(cfg, fd, |c, fd| c.stdin = Some(fd))
}

/// Set stdout FD on a config. Returns 0 on success, -1 on error.
///
/// # Safety
/// `cfg` must be a valid pointer.
#[cfg(unix)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_stdout_fd(cfg: *mut ArapucaConfig, fd: i32) -> i32 {
    set_config_fd(cfg, fd, |c, fd| c.stdout = Some(fd))
}

/// Set stderr FD on a config. Returns 0 on success, -1 on error.
///
/// # Safety
/// `cfg` must be a valid pointer.
#[cfg(unix)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_stderr_fd(cfg: *mut ArapucaConfig, fd: i32) -> i32 {
    set_config_fd(cfg, fd, |c, fd| c.stderr = Some(fd))
}

/// Set network proxy socket path on a config.
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_network_proxy(
    cfg: *mut ArapucaConfig,
    path: *const c_char,
) -> i32 {
    unsafe {
        set_config_string(cfg, path, |c, s| {
            c.network_proxy_socket = Some(PathBuf::from(s));
        })
    }
}

/// Add an allowed outbound host:port for the CONNECT proxy. Linux only.
///
/// When at least one allowed host is configured, `arapuca_sandbox_launch()`
/// automatically forks a CONNECT proxy (equivalent to `--allow-host` in the
/// CLI) and enables network namespace isolation.
///
/// `host` must be a valid ASCII hostname or domain suffix (leading `.` for
/// wildcard suffix matching, e.g. `.googleapis.com`). `port` must be 1-65535.
///
/// Returns 0 on success, -1 on error (call `arapuca_last_error()` for details).
///
/// # Safety
/// `cfg` must be a valid pointer from `arapuca_config_new()`. `host` must be
/// a valid null-terminated UTF-8 C string.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_add_allowed_host(
    cfg: *mut ArapucaConfig,
    host: *const c_char,
    port: u16,
) -> i32 {
    clear_error();
    let Some(cfg) = (unsafe { cfg.as_mut() }) else {
        set_error("null config pointer");
        return -1;
    };
    let Some(inner) = cfg.inner.as_mut() else {
        set_error("config already freed");
        return -1;
    };
    let host_str = match unsafe { validate_cstr(host) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return -1;
        }
    };
    if port == 0 {
        set_error("allowed host port must be 1-65535");
        return -1;
    }
    inner.allowed_hosts.push(crate::bridge::AllowedHost::new(
        host_str.to_ascii_lowercase(),
        port,
    ));
    0
}

/// Add a caller-supplied environment variable to the config.
///
/// Both key and value are validated (UTF-8, max 4096 bytes each).
/// Dangerous env vars (ARAPUCA_*, LD_*, etc.) are filtered at
/// launch time by the platform launcher, not here.
///
/// # Safety
/// All pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_add_env(
    cfg: *mut ArapucaConfig,
    key: *const c_char,
    value: *const c_char,
) -> i32 {
    clear_error();
    let Some(cfg) = (unsafe { cfg.as_mut() }) else {
        set_error("null config pointer");
        return -1;
    };
    let Some(inner) = cfg.inner.as_mut() else {
        set_error("config already freed");
        return -1;
    };
    let k = match unsafe { validate_cstr(key) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return -1;
        }
    };
    let v = match unsafe { validate_cstr(value) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return -1;
        }
    };
    inner.env.push((k, v));
    0
}

/// Callback type for receiving audit events as JSON.
///
/// # Safety contract
///
/// - `event_json` is valid only for the duration of the callback. The
///   callback must copy the data if it needs to retain it.
/// - `user_data` must remain valid until `arapuca_process_cleanup()`
///   returns. Passing stack or freed heap memory is undefined behavior.
/// - The callback may be invoked from any thread. The callback and
///   `user_data` must be safe for concurrent access.
/// - The callback must return normally. `longjmp`, C++ exceptions, and
///   Go panics in cgo callbacks are undefined behavior.
/// - The callback must not call any arapuca function (no reentrancy).
#[cfg(feature = "serde")]
pub type ArapucaAuditCallback = unsafe extern "C" fn(
    event_json: *const c_char,
    event_json_len: usize,
    user_data: *mut std::ffi::c_void,
);

#[cfg(feature = "serde")]
struct FfiAuditSink {
    callback: ArapucaAuditCallback,
    user_data: *mut std::ffi::c_void,
}

// SAFETY: The FFI contract documented above requires user_data to be
// thread-safe and to outlive the sandbox lifecycle. Non-local control
// flow from within the callback is documented as UB.
#[cfg(feature = "serde")]
unsafe impl Send for FfiAuditSink {}
#[cfg(feature = "serde")]
unsafe impl Sync for FfiAuditSink {}

#[cfg(feature = "serde")]
impl crate::audit::AuditSink for FfiAuditSink {
    fn emit(&self, event: crate::audit::AuditEvent) {
        let json = serde_json::to_string(&event)
            .unwrap_or_else(|_| r#"{"error":"audit event serialization failed"}"#.into());
        let cstr = match CString::new(json) {
            Ok(s) => s,
            Err(_) => return,
        };
        let ptr = cstr.as_ptr();
        let len = cstr.as_bytes().len();
        unsafe { (self.callback)(ptr, len, self.user_data) };
    }
}

/// Set an audit callback on a config. Requires the `serde` feature.
///
/// The callback receives JSON-serialized audit events during the
/// sandbox lifecycle. See `ArapucaAuditCallback` for the safety
/// contract.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `cfg` must be a valid pointer. `cb` must be a valid function pointer.
/// `user_data` must remain valid until `arapuca_process_cleanup()`.
#[cfg(feature = "serde")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_set_audit_callback(
    cfg: *mut ArapucaConfig,
    cb: Option<ArapucaAuditCallback>,
    user_data: *mut std::ffi::c_void,
) -> i32 {
    clear_error();
    let Some(cfg) = (unsafe { cfg.as_mut() }) else {
        set_error("null config pointer");
        return -1;
    };
    let Some(inner) = cfg.inner.as_mut() else {
        set_error("config already freed");
        return -1;
    };
    let Some(cb) = cb else {
        set_error("null callback pointer");
        return -1;
    };
    let sink = FfiAuditSink {
        callback: cb,
        user_data,
    };
    inner.audit_sink = Some(std::sync::Arc::new(sink));
    0
}

/// Free a config. Safe to call with NULL.
///
/// # Safety
/// `cfg` must be NULL or a valid pointer from `arapuca_config_new()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_config_free(cfg: *mut ArapucaConfig) {
    if !cfg.is_null() {
        let mut c = unsafe { Box::from_raw(cfg) };
        c.inner.take();
    }
}

// ─── Launch + Process API ───────────────────────────────────────────

/// Launch a sandboxed subprocess.
///
/// Returns NULL on error (check `arapuca_last_error()`).
///
/// # Safety
/// All pointers must be valid. `args` must have `args_count` entries.
/// `extra_fds` must have `extra_fds_count` entries (or be NULL if 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_launch(
    sb: *mut ArapucaSandbox,
    cfg: *const ArapucaConfig,
    cmd: *const c_char,
    args: *const *const c_char,
    args_count: usize,
    extra_fds: *const i32,
    extra_fds_count: usize,
) -> *mut ArapucaProcess {
    clear_error();

    // Validate sandbox.
    let Some(sb) = (unsafe { sb.as_mut() }) else {
        set_error("null sandbox pointer");
        return std::ptr::null_mut();
    };
    let Some(sandbox) = sb.inner.as_ref() else {
        set_error("sandbox already freed");
        return std::ptr::null_mut();
    };

    // Validate config.
    let Some(cfg) = (unsafe { cfg.as_ref() }) else {
        set_error("null config pointer");
        return std::ptr::null_mut();
    };
    let Some(config) = cfg.inner.as_ref() else {
        set_error("config already freed");
        return std::ptr::null_mut();
    };

    // Validate command.
    let cmd_str = match unsafe { validate_cstr(cmd) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return std::ptr::null_mut();
        }
    };

    // Parse args array.
    let mut arg_strings = Vec::with_capacity(args_count);
    if args_count > 0 {
        if args.is_null() {
            set_error("null args pointer with non-zero count");
            return std::ptr::null_mut();
        }
        for i in 0..args_count {
            let arg_ptr = unsafe { *args.add(i) };
            match unsafe { validate_cstr(arg_ptr) } {
                Ok(s) => arg_strings.push(s),
                Err(msg) => {
                    set_error(&format!("arg[{i}]: {msg}"));
                    return std::ptr::null_mut();
                }
            }
        }
    }
    let arg_refs: Vec<&str> = arg_strings.iter().map(|s| s.as_str()).collect();

    // Clone config and add extra FDs (Unix) or handles (Windows, future).
    let launch_config = {
        #[allow(unused_mut)]
        let mut cfg = config.clone();
        #[cfg(unix)]
        if extra_fds_count > 0 && !extra_fds.is_null() {
            for i in 0..extra_fds_count {
                cfg.extra_fds.push(unsafe { *extra_fds.add(i) } as RawFd);
            }
        }
        let _ = (extra_fds, extra_fds_count);
        cfg
    };

    // Launch.
    match sandbox.launch(&launch_config, &cmd_str, &arg_refs) {
        Ok(proc) => Box::into_raw(Box::new(ArapucaProcess { inner: Some(proc) })),
        Err(e) => {
            set_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Get the PID of a sandboxed process.
///
/// # Safety
/// `proc` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_process_pid(proc_: *const ArapucaProcess) -> u32 {
    let Some(proc_) = (unsafe { proc_.as_ref() }) else {
        return 0;
    };
    proc_.inner.as_ref().map_or(0, |p| p.pid())
}

/// Send a signal to a sandboxed process.
///
/// On Linux 5.3+, uses pidfd_send_signal for race-free delivery.
/// Falls back to kill() on older kernels or non-Linux platforms.
///
/// Returns 0 on success, -1 on error (check `arapuca_last_error()`).
///
/// # Safety
/// `proc` must be a valid pointer.
#[cfg(unix)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_process_signal(proc_: *const ArapucaProcess, signal: i32) -> i32 {
    clear_error();
    let Some(proc_) = (unsafe { proc_.as_ref() }) else {
        set_error("null process pointer");
        return -1;
    };
    let Some(process) = proc_.inner.as_ref() else {
        set_error("process already cleaned up");
        return -1;
    };
    match process.signal(signal) {
        Ok(()) => 0,
        Err(e) => {
            set_error(&e.to_string());
            -1
        }
    }
}

/// Wait for a sandboxed process to exit.
///
/// Returns:
/// - `>= 0`: exit code
/// - `< -1`: killed by signal (value = -signal_number)
/// - `-1`: error (check `arapuca_last_error()`)
///
/// # Safety
/// `proc` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_process_wait(proc_: *mut ArapucaProcess) -> i32 {
    clear_error();
    let Some(proc_) = (unsafe { proc_.as_mut() }) else {
        set_error("null process pointer");
        return -1;
    };
    let Some(process) = proc_.inner.as_mut() else {
        set_error("process already cleaned up");
        return -1;
    };

    match process.wait() {
        Ok(status) => {
            if let Some(code) = status.code() {
                return code;
            }
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(sig) = status.signal() {
                    return -sig;
                }
            }
            -1
        }
        Err(e) => {
            set_error(&format!("{e}"));
            -1
        }
    }
}

/// Read resource usage from the process's cgroup.
///
/// Must be called before `arapuca_process_cleanup()`.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// Both pointers must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_process_resource_stats(
    proc_: *const ArapucaProcess,
    out: *mut ArapucaResourceUsage,
) -> i32 {
    let Some(proc_) = (unsafe { proc_.as_ref() }) else {
        return -1;
    };
    let Some(out) = (unsafe { out.as_mut() }) else {
        return -1;
    };
    let Some(process) = proc_.inner.as_ref() else {
        return -1;
    };

    let stats = process.resource_stats();
    out.memory_current_bytes = stats.memory_current_bytes;
    out.memory_peak_bytes = stats.memory_peak_bytes;
    out.cpu_usage_seconds = stats.cpu_usage_seconds;
    out.pid_count = stats.pid_count;
    out.io_read_bytes = stats.io_read_bytes;
    out.io_write_bytes = stats.io_write_bytes;
    0
}

/// Read OOM kill count from the process's cgroup.
///
/// Must be called before `arapuca_process_cleanup()`.
///
/// # Safety
/// `proc` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_process_oom_count(proc_: *const ArapucaProcess) -> u32 {
    let Some(proc_) = (unsafe { proc_.as_ref() }) else {
        return 0;
    };
    proc_.inner.as_ref().map_or(0, |p| p.oom_count())
}

/// Clean up the sandbox temp directory, cgroup, and free the process handle.
/// Safe to call with NULL.
///
/// Must only be called after `arapuca_process_wait()` returns.
/// The pointer is invalid after this call.
///
/// # Safety
/// `proc` must be NULL or a valid pointer from `arapuca_launch()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_process_cleanup(proc_: *mut ArapucaProcess) {
    if !proc_.is_null() {
        let mut p = unsafe { Box::from_raw(proc_) };
        if let Some(process) = p.inner.take() {
            process.cleanup();
        }
    }
}

// ─── Apply API ──────────────────────────────────────────────────────

/// Enable Unix socket denial (Linux x86_64/aarch64 process isolation only).
/// Unsupported enabled requests fail at launch/application.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_profile_set_deny_unix_sockets(
    profile: *mut ArapucaProfile,
    enabled: bool,
) {
    if let Some(profile) = unsafe { profile.as_mut() } {
        if let Some(inner) = profile.inner.as_mut() {
            inner.deny_unix_sockets = enabled;
        }
    }
}

/// Apply sandbox restrictions to the current process. Fail-closed.
/// Returns 0 on success, -1 on error.
///
/// With Unix socket denial enabled, apply before untrusted execution in a
/// single-threaded process with exclusive FD-table ownership. No signal
/// handler may change descriptors during application. The caller must have
/// torn down all usable pre-existing io_uring contexts/submission mappings,
/// including descriptor-less registered rings and outstanding asynchronous
/// work. FD scanning cannot establish their absence; use fresh-exec launch
/// when these preconditions cannot be guaranteed.
///
/// # Safety
/// `profile` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_apply(profile: *const ArapucaProfile) -> i32 {
    clear_error();
    let Some(profile) = (unsafe { profile.as_ref() }) else {
        set_error("null profile pointer");
        return -1;
    };
    let Some(inner) = profile.inner.as_ref() else {
        set_error("profile already freed");
        return -1;
    };

    if let Err(e) = crate::wrapper::validate_unix_socket_policy(inner, true) {
        set_error(&e.to_string());
        return -1;
    }

    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64) };
        if ret != 0 {
            set_error(&format!(
                "PR_SET_NO_NEW_PRIVS: {}",
                std::io::Error::last_os_error()
            ));
            return -1;
        }
    }
    #[cfg(target_os = "linux")]
    if let Err(e) = crate::landlock::apply(inner, None) {
        set_error(&format!("landlock: {e}"));
        return -1;
    }
    #[cfg(seccomp_supported)]
    if let Err(e) = crate::seccomp::apply(&inner.seccomp_profile, inner.deny_unix_sockets) {
        set_error(&format!("seccomp: {e}"));
        return -1;
    }
    #[cfg(all(target_os = "linux", not(seccomp_supported)))]
    log::warn!("seccomp not available on this architecture");
    #[cfg(unix)]
    if let Err(e) = crate::rlimit::apply(inner) {
        set_error(&format!("rlimit: {e}"));
        return -1;
    }
    let _ = inner;
    0
}

// ─── Utility functions ──────────────────────────────────────────────

/// Create a socket directory (mode 0700, random suffix).
///
/// Returns a path string. Caller MUST free with `arapuca_free_string()`.
/// Returns NULL on error.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_make_socket_dir() -> *mut c_char {
    clear_error();
    match crate::env::make_socket_dir() {
        Ok(path) => match CString::new(path.to_string_lossy().as_bytes()) {
            Ok(cs) => cs.into_raw(),
            Err(e) => {
                set_error(&format!("path encoding: {e}"));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Create a temp directory for a task (random suffix).
///
/// Returns a path string. Caller MUST free with `arapuca_free_string()`.
/// Returns NULL on error.
///
/// # Safety
/// `task_id` must be a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_make_tmp_dir(task_id: *const c_char) -> *mut c_char {
    clear_error();
    let task_id = match unsafe { validate_cstr(task_id) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return std::ptr::null_mut();
        }
    };
    match crate::env::make_tmp_dir(&task_id) {
        Ok(path) => match CString::new(path.to_string_lossy().as_bytes()) {
            Ok(cs) => cs.into_raw(),
            Err(e) => {
                set_error(&format!("path encoding: {e}"));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

/// Find the arapuca wrapper binary.
///
/// Returns the path or NULL if not found.
/// Caller MUST free with `arapuca_free_string()`.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_wrapper_path() -> *mut c_char {
    match crate::env::wrapper_path() {
        Some(path) => match CString::new(path.to_string_lossy().as_bytes()) {
            Ok(cs) => cs.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// Enable selfexec mode: `wrapper_path()` returns `current_exe()`.
///
/// Call before the first launch. Once enabled, the consumer binary
/// acts as its own Landlock/seccomp trampoline — no separate
/// `arapuca` binary is needed.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_enable_selfexec_mode() {
    crate::selfexec::enable_selfexec_mode();
}

/// Calculate disk usage of a directory in MB.
///
/// Returns 0 on error or if the path doesn't exist.
///
/// # Safety
/// `path` must be a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_disk_usage_mb(path: *const c_char) -> u64 {
    let path = match unsafe { validate_cstr(path) } {
        Ok(s) => s,
        Err(_) => return 0,
    };
    crate::diskquota::usage_mb(std::path::Path::new(&path))
}

/// Free a string returned by arapuca.
///
/// MUST be used instead of `free()` — the string was allocated by
/// Rust's allocator, not the C allocator.
///
/// # Safety
/// `s` must be NULL or a pointer returned by a arapuca function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = unsafe { CString::from_raw(s) };
    }
}

// ─── Probes ─────────────────────────────────────────────────────────

/// Probe the Landlock ABI version. Returns 0 if unavailable.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_landlock_abi_version() -> u32 {
    #[cfg(target_os = "linux")]
    {
        crate::landlock::abi_version()
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Probe whether network namespace isolation is available.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_netns_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::netns::available()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

// ─── Error handling ─────────────────────────────────────────────────

/// Get the last error message. Returns NULL if no error.
///
/// The returned pointer is valid until the next arapuca call on
/// the same thread. Caller must NOT free it.
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_last_error() -> *const c_char {
    LAST_ERROR.with(|e| {
        let borrow = e.borrow();
        match borrow.as_ref() {
            Some(s) => s.as_ptr(),
            None => std::ptr::null(),
        }
    })
}

// ─── Internal helpers ───────────────────────────────────────────────

/// Validate a C string pointer: null-check, UTF-8, length bound.
///
/// # Safety
/// `ptr` must be either null or point to a valid null-terminated C string.
unsafe fn validate_cstr(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("null string pointer".into());
    }
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let s = cstr.to_str().map_err(|e| format!("invalid UTF-8: {e}"))?;
    if s.len() > MAX_STRING_LEN {
        return Err(format!(
            "string too long ({} bytes, max {MAX_STRING_LEN})",
            s.len()
        ));
    }
    Ok(s.to_string())
}

/// Helper to set a string field on a config.
///
/// # Safety
/// Both pointers must be valid.
unsafe fn set_config_string(
    cfg: *mut ArapucaConfig,
    value: *const c_char,
    setter: impl FnOnce(&mut Config, String),
) -> i32 {
    clear_error();
    let Some(cfg) = (unsafe { cfg.as_mut() }) else {
        set_error("null config pointer");
        return -1;
    };
    let Some(inner) = cfg.inner.as_mut() else {
        set_error("config already freed");
        return -1;
    };
    let s = match unsafe { validate_cstr(value) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return -1;
        }
    };
    setter(inner, s);
    0
}

// ─── Micro-VM API ──────────────────────────────────────────────────

/// Check whether micro-VM isolation is available on this system.
///
/// Returns true if KVM and qemu-img are available.
#[cfg(feature = "microvm")]
#[unsafe(no_mangle)]
pub extern "C" fn arapuca_microvm_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::platform::MicroVm::new()
            .and_then(|vm| {
                use crate::platform::Sandbox;
                vm.available()
            })
            .is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Pull (download and cache) a micro-VM image.
///
/// Returns the cached image path as a string. Caller MUST free
/// with `arapuca_free_string()`. Returns NULL on error.
///
/// # Safety
/// `distro` and `version` must be valid null-terminated strings.
#[cfg(feature = "microvm")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn arapuca_image_pull(
    distro: *const c_char,
    version: *const c_char,
) -> *mut c_char {
    clear_error();
    let distro = match unsafe { validate_cstr(distro) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return std::ptr::null_mut();
        }
    };
    let version = match unsafe { validate_cstr(version) } {
        Ok(s) => s,
        Err(msg) => {
            set_error(&msg);
            return std::ptr::null_mut();
        }
    };

    let source = crate::ImageSource::Distro {
        name: distro,
        version,
    };
    match crate::images::resolve(&source, &Default::default()) {
        Ok(cached) => match CString::new(cached.path.to_string_lossy().as_bytes()) {
            Ok(cs) => cs.into_raw(),
            Err(e) => {
                set_error(&format!("path encoding: {e}"));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(&format!("{e}"));
            std::ptr::null_mut()
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_create_and_free() {
        let p = arapuca_profile_new();
        assert!(!p.is_null());
        unsafe { arapuca_profile_free(p) };
    }

    #[test]
    fn profile_set_network_listeners() {
        let p = arapuca_profile_new();
        assert!(!p.is_null());
        unsafe {
            assert!(!(*p).inner.as_ref().unwrap().allow_network_listeners);
            arapuca_profile_set_network_listeners(p, true);
            assert!((*p).inner.as_ref().unwrap().allow_network_listeners);
            arapuca_profile_free(p);
        }
    }

    #[test]
    fn null_profile_free_is_safe() {
        unsafe { arapuca_profile_free(std::ptr::null_mut()) };
    }

    #[test]
    fn error_lifecycle() {
        clear_error();
        assert!(arapuca_last_error().is_null());

        set_error("test error");
        let err = arapuca_last_error();
        assert!(!err.is_null());
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
        assert_eq!(msg, "test error");

        clear_error();
        assert!(arapuca_last_error().is_null());
    }

    #[test]
    fn landlock_abi_version_probe() {
        let v = arapuca_landlock_abi_version();
        eprintln!("FFI landlock ABI: {v}");
    }

    #[test]
    fn sandbox_create_and_free() {
        let sb = arapuca_sandbox_new();
        assert!(!sb.is_null());
        unsafe { arapuca_sandbox_free(sb) };
    }

    #[test]
    fn null_sandbox_free_is_safe() {
        unsafe { arapuca_sandbox_free(std::ptr::null_mut()) };
    }

    #[test]
    fn config_create_and_free() {
        let cfg = arapuca_config_new();
        assert!(!cfg.is_null());
        unsafe { arapuca_config_free(cfg) };
    }

    #[test]
    fn config_set_fields() {
        let cfg = arapuca_config_new();
        let profile = arapuca_profile_new();

        unsafe {
            let task = CString::new("test-task").unwrap();
            let phase = CString::new("executing").unwrap();
            let dir = CString::new("/tmp/test").unwrap();

            assert_eq!(arapuca_config_set_task_id(cfg, task.as_ptr()), 0);
            assert_eq!(arapuca_config_set_phase(cfg, phase.as_ptr()), 0);
            assert_eq!(arapuca_config_set_socket_dir(cfg, dir.as_ptr()), 0);
            assert_eq!(arapuca_config_set_work_dir(cfg, dir.as_ptr()), 0);
            assert_eq!(arapuca_config_set_profile(cfg, profile), 0);
            #[cfg(unix)]
            {
                assert_eq!(arapuca_config_set_stdin_fd(cfg, 0), 0);
                assert_eq!(arapuca_config_set_stdout_fd(cfg, 1), 0);
                assert_eq!(arapuca_config_set_stderr_fd(cfg, 2), 0);

                // Negative FDs are rejected.
                assert_eq!(arapuca_config_set_stdin_fd(cfg, -1), -1);
                assert_eq!(arapuca_config_set_stdout_fd(cfg, -1), -1);
                assert_eq!(arapuca_config_set_stderr_fd(cfg, -1), -1);
            }

            let key = CString::new("MY_TOKEN").unwrap();
            let val = CString::new("secret123").unwrap();
            assert_eq!(arapuca_config_add_env(cfg, key.as_ptr(), val.as_ptr()), 0);

            let key2 = CString::new("CONFIG").unwrap();
            let val2 = CString::new("a=b=c").unwrap();
            assert_eq!(arapuca_config_add_env(cfg, key2.as_ptr(), val2.as_ptr()), 0);

            arapuca_profile_free(profile);
            arapuca_config_free(cfg);
        }
    }

    #[test]
    fn wrapper_path_returns_something() {
        let p = arapuca_wrapper_path();
        // May be NULL if arapuca binary not in PATH — that's fine.
        if !p.is_null() {
            unsafe { arapuca_free_string(p) };
        }
    }

    #[test]
    fn null_free_string_is_safe() {
        unsafe { arapuca_free_string(std::ptr::null_mut()) };
    }

    #[test]
    fn disk_usage_nonexistent() {
        let path = CString::new("/nonexistent-xyz-123").unwrap();
        let mb = unsafe { arapuca_disk_usage_mb(path.as_ptr()) };
        assert_eq!(mb, 0);
    }

    #[test]
    fn string_length_validation() {
        let long = "a".repeat(MAX_STRING_LEN + 1);
        let cs = CString::new(long).unwrap();
        let result = unsafe { validate_cstr(cs.as_ptr()) };
        assert!(result.is_err());
    }
}
