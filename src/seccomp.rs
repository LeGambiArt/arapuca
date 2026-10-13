//! Seccomp BPF syscall filtering.
//!
//! Uses the `seccompiler` crate (from AWS Firecracker) to construct and
//! install BPF filters that restrict which syscalls a sandboxed process
//! can make.
//!
//! Three tiers of response:
//! - **Tier 1 (KILL_PROCESS)**: Syscalls with no legitimate agent use
//!   (ptrace, mount, namespace manipulation, kernel modules, etc.).
//! - **Tier 2 (EPERM)**: Syscalls that may be probed by libraries
//!   (symlink, link, network sockets, clone with namespace flags, etc.).
//! - **Tier 3 (ENOSYS)**: `clone3` — forces runtime fallback to `clone`
//!   where namespace flags can be inspected via arg0.

use std::collections::HashMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::Error;

// ─── x32 ABI guard (x86_64 only) ─────────────────────────────────
//
// On x86_64, the x32 ABI shares AUDIT_ARCH_X86_64 but sets bit 30
// (__X32_SYSCALL_BIT = 0x40000000) in the syscall number. The
// seccompiler dependency validates the audit architecture but compares
// native syscall numbers exactly — x32-tagged numbers fall through to
// the default Allow action, bypassing all deny rules.
//
// This guard installs a stacked BPF filter that kills the process if
// any syscall number has the x32 bit set. It uses raw BPF because
// seccompiler's condition API operates on syscall arguments, not on
// the syscall number field itself.

// x32 guard constants — only needed on x86_64.
#[cfg(target_arch = "x86_64")]
mod x32 {
    /// `__X32_SYSCALL_BIT` — bit 30, set on all x32 ABI syscall numbers.
    pub const SYSCALL_BIT: u32 = 0x4000_0000;

    // BPF instruction constants (not re-exported by seccompiler).
    pub const BPF_LD: u16 = 0x00;
    pub const BPF_JMP: u16 = 0x05;
    pub const BPF_RET: u16 = 0x06;
    pub const BPF_W: u16 = 0x00;
    pub const BPF_ABS: u16 = 0x20;
    pub const BPF_JSET: u16 = 0x40;
    pub const BPF_K: u16 = 0x00;

    /// Offset of the `nr` field in `struct seccomp_data`.
    pub const SECCOMP_DATA_NR_OFFSET: u32 = 0;
}

/// Build a raw BPF filter that kills the process on x32 syscall numbers.
///
/// On x86_64, returns a 4-instruction program:
///   1. Load seccomp_data.nr
///   2. Test if __X32_SYSCALL_BIT is set (JSET)
///   3. If set → KILL_PROCESS
///   4. Otherwise → ALLOW
///
/// On aarch64 (no x32 ABI), returns `None`.
fn build_x32_guard() -> Option<BpfProgram> {
    #[cfg(target_arch = "x86_64")]
    {
        use seccompiler::sock_filter;
        use x32::*;
        let prog: BpfProgram = vec![
            // Load seccomp_data.nr (32-bit word at offset 0).
            sock_filter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: SECCOMP_DATA_NR_OFFSET,
            },
            // Test: nr & __X32_SYSCALL_BIT != 0?
            // jt=0 → next instruction (kill), jf=1 → skip to allow.
            sock_filter {
                code: BPF_JMP | BPF_JSET | BPF_K,
                jt: 0,
                jf: 1,
                k: SYSCALL_BIT,
            },
            // __X32_SYSCALL_BIT is set → kill.
            sock_filter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_KILL_PROCESS,
            },
            // __X32_SYSCALL_BIT is not set → allow (fall through to other filters).
            sock_filter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        Some(prog)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

// ─── Retained-resource validation ─────────────────────────────────
//
// When deny_unix_sockets is enabled, these helpers validate that the
// process holds no retained AF_UNIX sockets or io_uring ring FDs
// before seccomp filters are installed. Called from the wrapper
// trampolines and the direct-apply FFI entry point.

/// Validate that no inherited file descriptor is an AF_UNIX socket
/// or an io_uring ring.
///
/// Enumerates `/proc/self/fd` and inspects each descriptor:
/// - Sockets: `getsockopt(SO_DOMAIN)` — rejects `AF_UNIX`.
/// - io_uring rings: `/proc/self/fd/<n>` readlink target starts with
///   `anon_inode:[io_uring]`.
/// - Pipes, regular files, char devices: accepted (ENOTSOCK is expected).
///
/// Fails closed: directory-open, iteration, parsing, and unexpected
/// inspection errors reject application. Only `ENOTSOCK` from
/// `getsockopt` is an expected non-socket result (the descriptor is
/// then checked for io_uring identity).
///
/// The caller must ensure no concurrent descriptor-table mutations
/// (single-threaded context or exclusive ownership).
#[allow(dead_code)] // Callers wired in the next commit.
pub(crate) fn validate_no_retained_unix_resources() -> crate::Result<()> {
    let fd_dir = std::fs::read_dir("/proc/self/fd").map_err(|e| {
        Error::Validation(format!(
            "deny_unix_sockets: cannot enumerate /proc/self/fd: {e}"
        ))
    })?;

    // Keep the directory open through the entire scan so its own
    // descriptor does not become a stale entry.
    for entry in fd_dir {
        let entry = entry.map_err(|e| {
            Error::Validation(format!(
                "deny_unix_sockets: /proc/self/fd iteration error: {e}"
            ))
        })?;

        let name = entry.file_name();
        let fd_str = name.to_string_lossy();
        let fd: i32 = fd_str.parse().map_err(|_| {
            Error::Validation(format!(
                "deny_unix_sockets: unexpected /proc/self/fd entry: {fd_str}"
            ))
        })?;

        // Check if it's a socket and what domain it has.
        let mut domain: libc::c_int = 0;
        let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                &mut domain as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret == 0 {
            // It's a socket — reject AF_UNIX.
            if domain == libc::AF_UNIX {
                return Err(Error::Validation(format!(
                    "deny_unix_sockets: inherited AF_UNIX socket on fd {fd}"
                )));
            }
            // Non-AF_UNIX socket (e.g. AF_INET) — accepted.
            continue;
        }

        // getsockopt failed — check why.
        let errno = std::io::Error::last_os_error();
        let raw = errno.raw_os_error().unwrap_or(0);

        if raw == libc::ENOTSOCK {
            // Not a socket. Check if it's an io_uring ring FD via
            // /proc/self/fd/<n> readlink target.
            let link_path = format!("/proc/self/fd/{fd}");
            match std::fs::read_link(&link_path) {
                Ok(target) => {
                    let target_str = target.to_string_lossy();
                    if target_str.starts_with("anon_inode:[io_uring]") {
                        return Err(Error::Validation(format!(
                            "deny_unix_sockets: inherited io_uring ring on fd {fd}"
                        )));
                    }
                    // Regular file, pipe, char device, etc. — accepted.
                }
                Err(e) if e.raw_os_error() == Some(libc::EBADF) => {
                    // FD was closed between enumeration and readlink.
                    // Harmless race — the descriptor is gone.
                    continue;
                }
                Err(e) => {
                    return Err(Error::Validation(format!(
                        "deny_unix_sockets: cannot classify fd {fd}: readlink: {e}"
                    )));
                }
            }
            continue;
        }

        if raw == libc::EBADF {
            // FD was closed between enumeration and getsockopt.
            continue;
        }

        // Unexpected error — fail closed.
        return Err(Error::Validation(format!(
            "deny_unix_sockets: cannot inspect fd {fd}: getsockopt: {errno}"
        )));
    }

    Ok(())
}

/// Validate that the deny_unix_sockets policy can be enforced on
/// this platform and architecture.
///
/// Returns an error if seccomp is not supported (the creation-denial
/// filter cannot be installed). The caller should check this before
/// any irreversible restrictions.
#[allow(dead_code)] // Callers wired in the next commit.
pub(crate) fn validate_deny_unix_sockets_support() -> crate::Result<()> {
    if !cfg!(seccomp_supported) {
        return Err(Error::Validation(
            "deny_unix_sockets requires seccomp (Linux x86_64 or aarch64)".into(),
        ));
    }
    Ok(())
}

/// Validate that the calling process is single-threaded.
///
/// For the direct-apply path (`arapuca_apply`), the retained-resource
/// scan and seccomp installation must not race concurrent descriptor
/// mutations. This checks `/proc/self/task` and rejects if more than
/// one thread is detected. Propagates enumeration errors.
#[allow(dead_code)] // Callers wired in the next commit.
pub(crate) fn validate_single_threaded() -> crate::Result<()> {
    let task_dir = std::fs::read_dir("/proc/self/task").map_err(|e| {
        Error::Validation(format!(
            "deny_unix_sockets: cannot enumerate /proc/self/task: {e}"
        ))
    })?;

    let count = task_dir.count();
    if count > 1 {
        return Err(Error::Validation(format!(
            "deny_unix_sockets: direct apply requires single-threaded context \
             ({count} threads detected)"
        )));
    }
    if count == 0 {
        return Err(Error::Validation(
            "deny_unix_sockets: /proc/self/task is empty (unexpected)".into(),
        ));
    }

    Ok(())
}

/// Apply the seccomp BPF filter to the current process.
///
/// The filter restrictiveness depends on the profile:
/// - **Strict**: blocks AF_INET, symlink, memfd_create, io_uring, etc.
/// - **Baseline**: blocks only escape-critical syscalls (ptrace, mount,
///   namespace ops, kernel modules). Everything else allowed.
///
/// This calls `prctl(PR_SET_NO_NEW_PRIVS)` and then installs the filter.
/// After this call, the process is restricted to allowed syscalls. The
/// filter is inherited across `fork()` and `execve()`.
///
/// # Errors
///
/// Returns an error if filter construction or installation fails.
/// This is fail-closed — an error means the process is NOT filtered.
#[must_use = "seccomp errors must be handled — the process may be unfiltered"]
pub fn apply(profile: &crate::SeccompProfile) -> crate::Result<()> {
    match profile {
        crate::SeccompProfile::Strict => {
            let filter = build_filter()?;
            seccompiler::apply_filter(&filter).map_err(|e| Error::Seccomp(format!("{e}")))?;
            log::info!("seccomp: strict filter applied");
        }
        crate::SeccompProfile::Baseline => {
            let filter = build_baseline_filter()?;
            seccompiler::apply_filter(&filter).map_err(|e| Error::Seccomp(format!("{e}")))?;
            log::info!("seccomp: baseline filter applied");
        }
    }

    // Install the x32 ABI guard last (checked first by kernel due to
    // filter stacking). Kills the process if any syscall number has
    // __X32_SYSCALL_BIT set, preventing x32-tagged numbers from
    // reaching native deny rules that would otherwise miss them.
    if let Some(guard) = build_x32_guard() {
        seccompiler::apply_filter(&guard)
            .map_err(|e| Error::Seccomp(format!("install x32 guard: {e}")))?;
        log::info!("seccomp: x32 ABI guard installed");
    }

    Ok(())
}

/// Build the seccomp BPF filter program.
///
/// The filter uses a default-allow policy with explicit deny rules.
/// This matches the Go implementation's approach: block dangerous
/// syscalls, allow everything else.
fn build_filter() -> crate::Result<BpfProgram> {
    let arch = target_arch()?;

    // Collect all rules: syscall -> (action, conditions).
    let mut rules: HashMap<i64, Vec<SeccompRule>> = HashMap::new();

    // --- Tier 1: KILL_PROCESS ---
    let tier1_syscalls = tier1_kill_syscalls();
    for nr in tier1_syscalls {
        // Empty rule vector = match unconditionally.
        rules.insert(nr, vec![]);
    }

    // --- Tier 2: EPERM ---
    // These are handled by a separate filter since seccompiler only
    // supports one match action per filter. We install two filters:
    // first the EPERM filter (checked last by kernel), then the KILL
    // filter (checked first by kernel). Seccomp filters stack — the
    // most restrictive action wins.

    // Build and install the Tier 1 (KILL) filter.
    let kill_filter = SeccompFilter::new(
        rules.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build kill filter: {e}")))?;

    let kill_prog: BpfProgram =
        kill_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                Error::Seccomp(format!("compile kill filter: {e}"))
            })?;

    // Install KILL filter first (will be checked first by kernel due
    // to seccomp filter stacking — last installed is checked first).
    // Actually, we need to install the EPERM filter first so KILL
    // takes priority (last installed = checked first).

    // Build Tier 2 (EPERM) filter.
    let mut eperm_rules: HashMap<i64, Vec<SeccompRule>> = HashMap::new();
    for nr in tier2_eperm_syscalls() {
        eperm_rules.insert(nr, vec![]);
    }

    // Socket domain filtering: block AF_INET and AF_INET6.
    // socket(domain, type, protocol) — domain is arg0.
    let socket_inet = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_INET as u64,
        )
        .map_err(|e| Error::Seccomp(format!("socket AF_INET condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("socket AF_INET rule: {e}")))?;

    let socket_inet6 = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_INET6 as u64,
        )
        .map_err(|e| Error::Seccomp(format!("socket AF_INET6 condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("socket AF_INET6 rule: {e}")))?;

    eperm_rules.insert(libc::SYS_socket, vec![socket_inet, socket_inet6]);

    // prctl argument filtering: block all PR_SET_PDEATHSIG (any signal
    // value) and all non-zero PR_SET_DUMPABLE (including SUID_DUMP_ROOT=2).
    let prctl_block_pdeathsig = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::PR_SET_PDEATHSIG as u64,
        )
        .map_err(|e| Error::Seccomp(format!("prctl condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("prctl rule: {e}")))?;

    let prctl_set_dumpable = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::PR_SET_DUMPABLE as u64,
        )
        .map_err(|e| Error::Seccomp(format!("prctl condition: {e}")))?,
        SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, 0u64)
            .map_err(|e| Error::Seccomp(format!("prctl arg condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("prctl rule: {e}")))?;

    eperm_rules.insert(
        libc::SYS_prctl,
        vec![prctl_block_pdeathsig, prctl_set_dumpable],
    );

    // Block execveat with AT_EMPTY_PATH (fileless execution).
    // execveat(fd, "", ..., flags) — flags is arg4.
    let execveat_empty_path = SeccompRule::new(vec![
        SeccompCondition::new(
            4,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(libc::AT_EMPTY_PATH as u64),
            libc::AT_EMPTY_PATH as u64,
        )
        .map_err(|e| Error::Seccomp(format!("execveat condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("execveat rule: {e}")))?;

    eperm_rules.insert(libc::SYS_execveat, vec![execveat_empty_path]);

    // Block ioctl(fd, TIOCSTI/TIOCLINUX, ...) — terminal input injection.
    // On kernels < 6.2, a sandboxed process can inject keystrokes
    // into the parent's terminal via TIOCSTI on inherited FD 0.
    // TIOCLINUX subcommands 3+10 can achieve similar injection on
    // virtual consoles (not ptys) on kernels < 5.11.
    let ioctl_tiocsti = SeccompRule::new(vec![
        SeccompCondition::new(
            1,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            0x5412u64, // TIOCSTI
        )
        .map_err(|e| Error::Seccomp(format!("ioctl TIOCSTI condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("ioctl TIOCSTI rule: {e}")))?;
    let ioctl_tioclinux = SeccompRule::new(vec![
        SeccompCondition::new(
            1,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            0x541Cu64, // TIOCLINUX
        )
        .map_err(|e| Error::Seccomp(format!("ioctl TIOCLINUX condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("ioctl TIOCLINUX rule: {e}")))?;

    eperm_rules.insert(libc::SYS_ioctl, vec![ioctl_tiocsti, ioctl_tioclinux]);

    // Block kill() with pid <= 0 (broadcast/group signals).
    // pid <= 0 covers kill(-1, sig) (all processes), kill(0, sig)
    // (process group), and kill(-pgid, sig) (specific group).
    // Safe for positive PIDs: Linux pid_max <= 4194304 (0x400000),
    // so no legitimate positive PID has bit 31 set.
    let kill_zero = SeccompRule::new(vec![
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 0u64)
            .map_err(|e| Error::Seccomp(format!("kill zero condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("kill zero rule: {e}")))?;
    let kill_negative = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(0x80000000),
            0x80000000,
        )
        .map_err(|e| Error::Seccomp(format!("kill negative condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("kill negative rule: {e}")))?;
    eperm_rules.insert(libc::SYS_kill, vec![kill_zero, kill_negative]);

    // Block tkill unconditionally (deprecated, superseded by tgkill).
    eperm_rules.insert(libc::SYS_tkill, vec![]);

    // Block clone(2) with any CLONE_NEW* namespace flag. One rule per
    // flag — seccompiler OR's multiple rules for the same syscall.
    // Uses Qword (64-bit) to match the unsigned long flags argument.
    let clone_ns_flags: &[(i64, &str)] = &[
        (0x0002_0000, "CLONE_NEWNS"),
        (0x0200_0000, "CLONE_NEWCGROUP"),
        (0x0400_0000, "CLONE_NEWUTS"),
        (0x0800_0000, "CLONE_NEWIPC"),
        (0x1000_0000, "CLONE_NEWUSER"),
        (0x2000_0000, "CLONE_NEWPID"),
        (0x4000_0000, "CLONE_NEWNET"),
        (0x0000_0080, "CLONE_NEWTIME"),
    ];

    let mut clone_rules = Vec::new();
    for &(flag, name) in clone_ns_flags {
        let rule = SeccompRule::new(vec![
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(flag as u64),
                flag as u64,
            )
            .map_err(|e| Error::Seccomp(format!("clone {name} condition: {e}")))?,
        ])
        .map_err(|e| Error::Seccomp(format!("clone {name} rule: {e}")))?;
        clone_rules.push(rule);
    }
    eperm_rules.insert(libc::SYS_clone, clone_rules);

    // NOTE: we do NOT block seccomp(SET_MODE_FILTER) because seccomp
    // filters stack — new filters can only be more restrictive (kernel
    // takes the most restrictive action across all filters). Blocking it
    // would also prevent our three-phase filter installation.

    // --- ENOSYS filter for clone3 and io_uring ---
    // clone3: return ENOSYS so Go/glibc fall back to clone(2), where
    // we CAN inspect flags via arg0 (Chromium/Firefox approach).
    // io_uring_*: return ENOSYS so libraries (libuv, liburing) fall
    // back to epoll/poll. Matches kernel sysctl io_uring_disabled=2.
    let mut enosys_rules: HashMap<i64, Vec<SeccompRule>> = HashMap::new();
    enosys_rules.insert(libc::SYS_clone3, vec![]);
    enosys_rules.insert(libc::SYS_io_uring_setup, vec![]);
    enosys_rules.insert(libc::SYS_io_uring_enter, vec![]);
    enosys_rules.insert(libc::SYS_io_uring_register, vec![]);

    let enosys_filter = SeccompFilter::new(
        enosys_rules.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build enosys filter: {e}")))?;

    let enosys_prog: BpfProgram =
        enosys_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                Error::Seccomp(format!("compile enosys filter: {e}"))
            })?;

    let eperm_filter = SeccompFilter::new(
        eperm_rules.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build eperm filter: {e}")))?;

    let eperm_prog: BpfProgram =
        eperm_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                Error::Seccomp(format!("compile eperm filter: {e}"))
            })?;

    // Install order: ENOSYS → EPERM → KILL (last installed checked
    // first by kernel). The kernel takes the most restrictive action
    // across all filters: KILL > ERRNO > ALLOW. The ENOSYS and EPERM
    // filters target different syscalls (no overlap), so the equal
    // precedence of ERRNO values is not a concern.
    seccompiler::apply_filter(&enosys_prog)
        .map_err(|e| Error::Seccomp(format!("install enosys filter: {e}")))?;
    seccompiler::apply_filter(&eperm_prog)
        .map_err(|e| Error::Seccomp(format!("install eperm filter: {e}")))?;

    Ok(kill_prog)
}

// LSM syscalls (kernel 6.8+, generic table — same NR on x86_64/aarch64).
// Not yet in the libc crate for these architectures.
// TODO: replace with libc::SYS_lsm_* when the libc crate adds them.
// Reference: include/uapi/asm-generic/unistd.h
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYS_LSM_GET_SELF_ATTR: i64 = 459;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYS_LSM_SET_SELF_ATTR: i64 = 460;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYS_LSM_LIST_MODULES: i64 = 461;

/// Tier 1 syscalls: KILL_PROCESS on match.
/// No legitimate use by sandboxed agents.
fn tier1_kill_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        #[cfg(any(target_arch = "x86_64", target_env = "gnu"))]
        libc::SYS_kexec_file_load,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_personality,
        libc::SYS_memfd_create,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_userfaultfd,
        libc::SYS_kcmp,
        // io_uring_* in ENOSYS tier — libraries probe and fall back.
        libc::SYS_bpf,
        libc::SYS_mount_setattr,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        libc::SYS_process_madvise,
        libc::SYS_memfd_secret,
        libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_add_rule,
        libc::SYS_landlock_restrict_self,
        libc::SYS_quotactl,
        libc::SYS_quotactl_fd,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        SYS_LSM_GET_SELF_ATTR,
        SYS_LSM_SET_SELF_ATTR,
        SYS_LSM_LIST_MODULES,
    ]
}

/// Tier 2 syscalls: EPERM on match (unconditional).
/// May be probed by libraries; returning EPERM is less disruptive
/// than killing the process.
fn tier2_eperm_syscalls() -> Vec<i64> {
    #[allow(unused_mut)]
    let mut v = vec![
        libc::SYS_symlinkat,
        libc::SYS_linkat,
        libc::SYS_perf_event_open,
    ];
    #[cfg(target_arch = "x86_64")]
    {
        v.push(libc::SYS_symlink);
        v.push(libc::SYS_link);
    }
    v
}

/// Summary of the seccomp filter policy for audit reporting.
pub(crate) struct SeccompSummary {
    pub tier1_kill_count: usize,
    /// Count of unconditional EPERM syscalls only (symlinkat, linkat, etc.).
    /// Does not include argument-filtered rules (socket domain check,
    /// prctl argument check, execveat AT_EMPTY_PATH check, clone namespace
    /// flags check) — those are reported as separate bool flags below.
    pub tier2_eperm_count: usize,
    pub socket_filter: bool,
    pub prctl_filter: bool,
    pub clone_ns_filter: bool,
    pub clone3_enosys: bool,
    pub io_uring_enosys: bool,
    pub execveat_filter: bool,
    pub kill_filter: bool,
}

pub(crate) fn summary(profile: &crate::SeccompProfile) -> SeccompSummary {
    match profile {
        crate::SeccompProfile::Strict => SeccompSummary {
            tier1_kill_count: tier1_kill_syscalls().len(),
            tier2_eperm_count: tier2_eperm_syscalls().len(),
            socket_filter: true,
            prctl_filter: true,
            clone_ns_filter: true,
            clone3_enosys: true,
            io_uring_enosys: true,
            execveat_filter: true,
            kill_filter: true,
        },
        crate::SeccompProfile::Baseline => SeccompSummary {
            tier1_kill_count: baseline_kill_syscalls().len(),
            tier2_eperm_count: 2, // tkill + perf_event_open
            socket_filter: false,
            prctl_filter: true,
            clone_ns_filter: true,
            clone3_enosys: true,
            io_uring_enosys: true,
            execveat_filter: true,
            kill_filter: true,
        },
    }
}

/// Syscalls unconditionally blocked in the baseline profile.
fn baseline_kill_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_mount_setattr,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_personality,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        #[cfg(any(target_arch = "x86_64", target_env = "gnu"))]
        libc::SYS_kexec_file_load,
        libc::SYS_reboot,
        libc::SYS_bpf,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_add_rule,
        libc::SYS_landlock_restrict_self,
        libc::SYS_userfaultfd,
        SYS_LSM_SET_SELF_ATTR,
        // io_uring_* in ENOSYS tier — libraries probe and fall back.
        libc::SYS_memfd_create,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        libc::SYS_kcmp,
        libc::SYS_process_madvise,
        libc::SYS_memfd_secret,
        libc::SYS_quotactl,
        libc::SYS_quotactl_fd,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        SYS_LSM_GET_SELF_ATTR,
        SYS_LSM_LIST_MODULES,
    ]
}

/// Build the baseline seccomp filter (default-allow, explicit deny).
///
/// Blocks escape-critical syscalls unconditionally, plus clone() with
/// namespace flags and clone3 (returns ENOSYS to force fallback to
/// clone where flags can be inspected).
fn build_baseline_filter() -> crate::Result<BpfProgram> {
    let arch = target_arch()?;

    let mut deny: HashMap<i64, Vec<SeccompRule>> = HashMap::new();
    for nr in baseline_kill_syscalls() {
        deny.insert(nr, vec![]);
    }

    let filter = SeccompFilter::new(
        deny.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build baseline filter: {e}")))?;

    let main_prog: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| Error::Seccomp(format!("compile baseline: {e}")))?;

    // Stacked filter: block clone with namespace flags.
    // Default action = Allow (non-clone syscalls pass through).
    // Match action = Errno(EPERM) (clone with ns flags is denied).
    // We insert clone with a condition that matches when ANY
    // CLONE_NEW* flag is set. MaskedEq(CLONE_NEW_FLAGS, 0) matches
    // when no ns flags → we want the inverse.
    //
    // Approach: use a default-KillProcess filter that ALLOWS clone
    // only when no namespace flags are set. Other syscalls get
    // Allow (they're in the map with empty rules). clone without
    // ns flags also gets Allow. clone WITH ns flags falls through
    // to mismatch (KillProcess).
    //
    // Actually the simplest approach: use an EPERM filter for clone
    // with ns flags, matching the strict mode pattern.
    let mut clone_deny: HashMap<i64, Vec<SeccompRule>> = HashMap::new();

    // clone: kill if any CLONE_NEW* flag is present.
    // MaskedEq(mask, mask) matches when ALL bits in mask are set.
    // But we want to match when ANY bit is set. BPF can't do OR
    // directly. The strict mode uses 8 separate conditions ANDed
    // in one rule — that would match only when ALL 8 flags are set.
    //
    // Looking at the strict mode code: it uses
    // MaskedEq(CLONE_NEWNS, CLONE_NEWNS) for each flag in separate
    // rules. Multiple rules in the Vec are ORed — if ANY rule
    // matches, the action fires. So we need one rule per flag.
    let ns_flags = [
        libc::CLONE_NEWNS as u64,
        libc::CLONE_NEWCGROUP as u64,
        libc::CLONE_NEWUTS as u64,
        libc::CLONE_NEWIPC as u64,
        libc::CLONE_NEWUSER as u64,
        libc::CLONE_NEWPID as u64,
        libc::CLONE_NEWNET as u64,
        0x0000_0080, // CLONE_NEWTIME (Linux 5.6+, not yet in libc crate)
    ];
    let mut clone_rules = Vec::new();
    for flag in ns_flags {
        clone_rules.push(
            SeccompRule::new(vec![
                SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Qword,
                    SeccompCmpOp::MaskedEq(flag),
                    flag,
                )
                .map_err(|e| Error::Seccomp(format!("clone flag condition: {e}")))?,
            ])
            .map_err(|e| Error::Seccomp(format!("clone flag rule: {e}")))?,
        );
    }
    clone_deny.insert(libc::SYS_clone, clone_rules);

    // clone3 is handled by a separate ENOSYS stacked filter below.
    // Do NOT add it to the deny map — KillProcess would override
    // the ENOSYS (seccomp takes the most restrictive action).

    let clone_filter = SeccompFilter::new(
        clone_deny.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build baseline clone filter: {e}")))?;

    let clone_prog: BpfProgram =
        clone_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                Error::Seccomp(format!("compile baseline clone filter: {e}"))
            })?;

    // ENOSYS filter for clone3 and io_uring (same pattern as strict mode).
    let mut enosys_rules: HashMap<i64, Vec<SeccompRule>> = HashMap::new();
    enosys_rules.insert(libc::SYS_clone3, vec![]);
    enosys_rules.insert(libc::SYS_io_uring_setup, vec![]);
    enosys_rules.insert(libc::SYS_io_uring_enter, vec![]);
    enosys_rules.insert(libc::SYS_io_uring_register, vec![]);
    let enosys_filter = SeccompFilter::new(
        enosys_rules.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build baseline enosys filter: {e}")))?;
    let enosys_prog: BpfProgram =
        enosys_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                Error::Seccomp(format!("compile baseline enosys filter: {e}"))
            })?;

    // Install stacked filters: ENOSYS first, then clone deny, then main.
    // Last installed is checked first; most restrictive action wins.
    seccompiler::apply_filter(&enosys_prog)
        .map_err(|e| Error::Seccomp(format!("install baseline enosys filter: {e}")))?;
    seccompiler::apply_filter(&clone_prog)
        .map_err(|e| Error::Seccomp(format!("install baseline clone filter: {e}")))?;

    // Consolidated EPERM filter for all argument-filtered rules.
    // A single stacked filter reduces BPF evaluation overhead.
    let mut eperm_rules: HashMap<i64, Vec<SeccompRule>> = HashMap::new();

    // prctl(PR_SET_PDEATHSIG, *) and prctl(PR_SET_DUMPABLE, non-zero)
    let baseline_prctl_pdeathsig = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::PR_SET_PDEATHSIG as u64,
        )
        .map_err(|e| Error::Seccomp(format!("baseline prctl condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("baseline prctl rule: {e}")))?;
    let baseline_prctl_dumpable = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::PR_SET_DUMPABLE as u64,
        )
        .map_err(|e| Error::Seccomp(format!("baseline prctl condition: {e}")))?,
        SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, 0u64)
            .map_err(|e| Error::Seccomp(format!("baseline prctl arg condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("baseline prctl rule: {e}")))?;
    eperm_rules.insert(
        libc::SYS_prctl,
        vec![baseline_prctl_pdeathsig, baseline_prctl_dumpable],
    );

    // execveat with AT_EMPTY_PATH (fileless execution)
    eperm_rules.insert(
        libc::SYS_execveat,
        vec![
            SeccompRule::new(vec![
                SeccompCondition::new(
                    4,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::MaskedEq(libc::AT_EMPTY_PATH as u64),
                    libc::AT_EMPTY_PATH as u64,
                )
                .map_err(|e| Error::Seccomp(format!("baseline execveat condition: {e}")))?,
            ])
            .map_err(|e| Error::Seccomp(format!("baseline execveat rule: {e}")))?,
        ],
    );

    // ioctl(TIOCSTI/TIOCLINUX) — terminal input injection
    eperm_rules.insert(
        libc::SYS_ioctl,
        vec![
            SeccompRule::new(vec![
                SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 0x5412u64)
                    .map_err(|e| Error::Seccomp(format!("baseline ioctl condition: {e}")))?,
            ])
            .map_err(|e| Error::Seccomp(format!("baseline ioctl rule: {e}")))?,
            SeccompRule::new(vec![
                SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 0x541Cu64)
                    .map_err(|e| Error::Seccomp(format!("baseline ioctl condition: {e}")))?,
            ])
            .map_err(|e| Error::Seccomp(format!("baseline ioctl rule: {e}")))?,
        ],
    );

    // kill(pid <= 0) — broadcast/group signals
    let kill_zero = SeccompRule::new(vec![
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 0u64)
            .map_err(|e| Error::Seccomp(format!("baseline kill zero condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("baseline kill zero rule: {e}")))?;
    let kill_negative = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(0x80000000),
            0x80000000,
        )
        .map_err(|e| Error::Seccomp(format!("baseline kill negative condition: {e}")))?,
    ])
    .map_err(|e| Error::Seccomp(format!("baseline kill negative rule: {e}")))?;
    eperm_rules.insert(libc::SYS_kill, vec![kill_zero, kill_negative]);

    // tkill — deprecated, block unconditionally
    eperm_rules.insert(libc::SYS_tkill, vec![]);

    // perf_event_open — may be probed by profiling libraries
    eperm_rules.insert(libc::SYS_perf_event_open, vec![]);

    let eperm_filter = SeccompFilter::new(
        eperm_rules.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("build baseline eperm filter: {e}")))?;
    let eperm_prog: BpfProgram =
        eperm_filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                Error::Seccomp(format!("compile baseline eperm filter: {e}"))
            })?;
    seccompiler::apply_filter(&eperm_prog)
        .map_err(|e| Error::Seccomp(format!("install baseline eperm filter: {e}")))?;

    Ok(main_prog)
}

/// Determine the target architecture for seccompiler.
pub(crate) fn target_arch() -> crate::Result<TargetArch> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(TargetArch::x86_64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(TargetArch::aarch64)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(Error::Seccomp(format!(
            "unsupported architecture: {}",
            std::env::consts::ARCH
        )))
    }
}

// ─── Syscall name table ───────────────────────────────────────────

/// Map a syscall number to a human-readable name for debug output.
///
/// Covers syscalls commonly found in seccomp allowlists and glibc
/// runtime internals. Returns `"unknown"` for unmapped numbers.
#[cfg(target_arch = "x86_64")]
pub(crate) fn syscall_name(nr: i64) -> &'static str {
    match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        6 => "lstat",
        7 => "poll",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        15 => "rt_sigreturn",
        16 => "ioctl",
        17 => "pread64",
        20 => "writev",
        23 => "select",
        24 => "sched_yield",
        25 => "mremap",
        28 => "madvise",
        35 => "nanosleep",
        39 => "getpid",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        48 => "shutdown",
        49 => "bind",
        51 => "getsockname",
        52 => "getpeername",
        54 => "setsockopt",
        55 => "getsockopt",
        56 => "clone",
        59 => "execve",
        60 => "exit",
        63 => "uname",
        72 => "fcntl",
        79 => "getcwd",
        97 => "getrlimit",
        102 => "getuid",
        104 => "getgid",
        107 => "geteuid",
        108 => "getegid",
        131 => "sigaltstack",
        157 => "prctl",
        186 => "gettid",
        202 => "futex",
        203 => "sched_setaffinity",
        204 => "sched_getaffinity",
        217 => "getdents64",
        218 => "set_tid_address",
        228 => "clock_gettime",
        230 => "clock_nanosleep",
        231 => "exit_group",
        232 => "epoll_wait",
        233 => "epoll_ctl",
        234 => "tgkill",
        257 => "openat",
        262 => "newfstatat",
        270 => "pselect6",
        281 => "epoll_create1",
        288 => "accept4",
        291 => "epoll_pwait",
        299 => "recvmmsg",
        302 => "prlimit64",
        303 => "sendmmsg",
        309 => "getcpu",
        318 => "getrandom",
        332 => "statx",
        334 => "rseq",
        435 => "clone3",
        437 => "openat2",
        _ => "unknown",
    }
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn syscall_name(nr: i64) -> &'static str {
    match nr {
        25 => "fcntl",
        29 => "ioctl",
        35 => "unlinkat",
        43 => "statfs",
        46 => "ftruncate",
        48 => "faccessat",
        49 => "chdir",
        56 => "openat",
        57 => "close",
        61 => "getdents64",
        62 => "lseek",
        63 => "read",
        64 => "write",
        66 => "writev",
        67 => "pread64",
        72 => "pselect6",
        73 => "ppoll",
        78 => "readlinkat",
        79 => "newfstatat",
        80 => "fstat",
        93 => "exit",
        94 => "exit_group",
        96 => "set_tid_address",
        98 => "futex",
        99 => "set_robust_list",
        100 => "get_robust_list",
        101 => "nanosleep",
        113 => "clock_gettime",
        115 => "clock_nanosleep",
        117 => "ptrace",
        123 => "sched_getaffinity",
        124 => "sched_yield",
        129 => "kill",
        130 => "tkill",
        131 => "tgkill",
        132 => "sigaltstack",
        134 => "rt_sigaction",
        135 => "rt_sigprocmask",
        139 => "rt_sigreturn",
        160 => "uname",
        167 => "prctl",
        172 => "getpid",
        175 => "getuid",
        176 => "getgid",
        177 => "geteuid",
        178 => "getegid",
        186 => "gettid",
        198 => "socket",
        200 => "bind",
        202 => "accept",
        203 => "connect",
        204 => "getsockname",
        205 => "getpeername",
        206 => "sendto",
        207 => "recvfrom",
        208 => "setsockopt",
        209 => "getsockopt",
        210 => "shutdown",
        211 => "sendmsg",
        212 => "recvmsg",
        214 => "brk",
        215 => "munmap",
        216 => "mremap",
        220 => "clone",
        221 => "execve",
        222 => "mmap",
        226 => "mprotect",
        228 => "madvise",
        233 => "accept4",
        242 => "recvmmsg",
        243 => "sendmmsg",
        261 => "prlimit64",
        270 => "process_vm_readv",
        271 => "getcpu",
        278 => "getrandom",
        281 => "epoll_create1",
        282 => "epoll_ctl",
        283 => "epoll_pwait",
        291 => "statx",
        293 => "rseq",
        435 => "clone3",
        437 => "openat2",
        _ => "unknown",
    }
}

// ─── Seccomp debug handler ────────────────────────────────────────

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static HANDLER_ACTIVE: AtomicBool = AtomicBool::new(false);
static REPORTED_SYSCALLS: [AtomicU64; 8] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

// SAFETY: This handler MUST remain async-signal-safe.
// - No heap allocation (no format!(), no Vec, no String)
// - No Rust I/O (no eprintln!, no stderr().write())
// - Only libc::write(2, ...) for output
// - syscall_name() is a pure match returning &'static str
// - SYS_write MUST remain in all seccomp allowlists
// Violating any of these causes infinite SIGSYS recursion under SA_NODEFER.
extern "C" fn sigsys_handler(
    _sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ucontext: *mut libc::c_void,
) {
    // Re-entrance guard: if our write(2) was itself trapped, bail.
    if HANDLER_ACTIVE.swap(true, Ordering::Relaxed) {
        return;
    }

    if info.is_null() {
        HANDLER_ACTIVE.store(false, Ordering::Relaxed);
        return;
    }

    // Extract si_syscall from siginfo_t at byte offset 0x18 (24).
    // This is offsetof(_sifields) + sizeof(void*) = 16 + 8 on LP64.
    // Stable kernel ABI on both x86_64 and aarch64.
    let nr = unsafe {
        let ptr = info as *const u8;
        *(ptr.add(0x18) as *const i32)
    } as i64;

    // Dedup: only report each syscall number once.
    // 512-bit bitset covers syscalls 0-511 (all current Linux syscalls).
    let nr_u = nr as u64;
    let idx = (nr_u / 64) as usize;
    if idx < REPORTED_SYSCALLS.len() {
        let bit = 1u64 << (nr_u % 64);
        let prev = REPORTED_SYSCALLS[idx].fetch_or(bit, Ordering::Relaxed);
        if prev & bit != 0 {
            HANDLER_ACTIVE.store(false, Ordering::Relaxed);
            return;
        }
    }

    let name = syscall_name(nr);

    // Format into a stack buffer: "seccomp: blocked syscall NNN (name)\n"
    let mut buf = [0u8; 128];
    let prefix = b"seccomp: blocked syscall ";
    let mut pos = prefix.len();
    buf[..pos].copy_from_slice(prefix);

    // Integer to decimal (async-signal-safe, no allocation).
    let nr_abs = if nr < 0 { -(nr as i128) } else { nr as i128 } as u64;
    if nr < 0 {
        buf[pos] = b'-';
        pos += 1;
    }
    let mut digits = [0u8; 20];
    let mut dpos = 0;
    let mut n = nr_abs;
    if n == 0 {
        digits[0] = b'0';
        dpos = 1;
    } else {
        while n > 0 {
            digits[dpos] = b'0' + (n % 10) as u8;
            n /= 10;
            dpos += 1;
        }
    }
    for i in (0..dpos).rev() {
        if pos < buf.len() {
            buf[pos] = digits[i];
            pos += 1;
        }
    }

    // Append " (name)\n"
    let suffix_len = 2 + name.len() + 2; // " (" + name + ")\n"
    if pos + suffix_len <= buf.len() {
        buf[pos] = b' ';
        buf[pos + 1] = b'(';
        pos += 2;
        buf[pos..pos + name.len()].copy_from_slice(name.as_bytes());
        pos += name.len();
        buf[pos] = b')';
        buf[pos + 1] = b'\n';
        pos += 2;
    } else if pos < buf.len() {
        buf[pos] = b'\n';
        pos += 1;
    }

    unsafe { libc::write(2, buf.as_ptr().cast(), pos) };

    HANDLER_ACTIVE.store(false, Ordering::Relaxed);
}

/// Install a SIGSYS handler for seccomp debug mode.
///
/// When seccomp filters use `SECCOMP_RET_TRAP` (debug mode) instead
/// of `SECCOMP_RET_KILL_PROCESS`, blocked syscalls deliver SIGSYS.
/// This handler prints the blocked syscall number and name to stderr,
/// then returns (the syscall returns -ENOSYS to the caller).
///
/// Must be called BEFORE seccomp filters are applied. Each blocked
/// syscall number is reported only once (deduplication via bitset).
pub(crate) fn install_seccomp_debug_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigsys_handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER;
        if libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut()) != 0 {
            let msg = b"seccomp debug: failed to install SIGSYS handler\n";
            libc::write(2, msg.as_ptr().cast(), msg.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_name_matches_libc_constants() {
        let checks: &[(i64, &str)] = &[
            (libc::SYS_read, "read"),
            (libc::SYS_write, "write"),
            (libc::SYS_close, "close"),
            (libc::SYS_openat, "openat"),
            (libc::SYS_mmap, "mmap"),
            (libc::SYS_clone, "clone"),
            (libc::SYS_clone3, "clone3"),
            (libc::SYS_execve, "execve"),
            (libc::SYS_exit_group, "exit_group"),
            (libc::SYS_socket, "socket"),
            (libc::SYS_connect, "connect"),
            (libc::SYS_futex, "futex"),
            (libc::SYS_rt_sigaction, "rt_sigaction"),
            (libc::SYS_sched_getaffinity, "sched_getaffinity"),
            (libc::SYS_fcntl, "fcntl"),
            (libc::SYS_nanosleep, "nanosleep"),
            (libc::SYS_clock_gettime, "clock_gettime"),
            (libc::SYS_statx, "statx"),
            (libc::SYS_getrandom, "getrandom"),
            (libc::SYS_prctl, "prctl"),
        ];
        for &(nr, expected) in checks {
            assert_eq!(
                syscall_name(nr),
                expected,
                "syscall_name({nr}) should be \"{expected}\""
            );
        }
    }

    #[test]
    fn tier1_count_is_exact() {
        #[cfg(any(target_arch = "x86_64", target_env = "gnu"))]
        let expected = 45;
        #[cfg(not(any(target_arch = "x86_64", target_env = "gnu")))]
        let expected = 44; // kexec_file_load absent on aarch64-musl
        assert_eq!(
            tier1_kill_syscalls().len(),
            expected,
            "tier1 count changed — update this assertion if intentional"
        );
    }

    #[test]
    fn tier2_count_is_exact() {
        #[cfg(target_arch = "x86_64")]
        let expected = 5;
        #[cfg(target_arch = "aarch64")]
        let expected = 3;
        assert_eq!(
            tier2_eperm_syscalls().len(),
            expected,
            "tier2 count changed — update this assertion if intentional"
        );
    }

    #[test]
    fn tier1_no_duplicates() {
        let syscalls = tier1_kill_syscalls();
        let mut seen = std::collections::HashSet::new();
        for nr in &syscalls {
            assert!(seen.insert(nr), "duplicate tier1 syscall: {nr}");
        }
    }

    #[test]
    fn tier2_no_duplicates() {
        let syscalls = tier2_eperm_syscalls();
        let mut seen = std::collections::HashSet::new();
        for nr in &syscalls {
            assert!(seen.insert(nr), "duplicate tier2 syscall: {nr}");
        }
    }

    #[test]
    fn no_tier_overlap() {
        let t1: std::collections::HashSet<i64> = tier1_kill_syscalls().into_iter().collect();
        let t2: std::collections::HashSet<i64> = tier2_eperm_syscalls().into_iter().collect();
        let overlap: Vec<_> = t1.intersection(&t2).collect();
        assert!(overlap.is_empty(), "syscalls in both tiers: {overlap:?}");
    }

    #[test]
    fn target_arch_resolves() {
        assert!(target_arch().is_ok());
    }

    #[test]
    fn filter_builds() {
        // Verify the filter compiles without error.
        // We don't apply it here because that would restrict this test process.
        assert!(build_filter().is_ok());
    }

    /// Fork a child, apply the seccomp filter, run `test_fn`, and
    /// check the exit status. Returns (exited_normally, exit_code_or_signal).
    fn run_in_filtered_child(test_fn: fn()) -> (bool, i32) {
        // SAFETY: fork is safe here — single-threaded test process.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            // Child: apply filter and run the test.
            if let Err(e) = apply(&crate::SeccompProfile::Strict) {
                eprintln!("seccomp apply failed: {e}");
                unsafe { libc::_exit(99) };
            }
            test_fn();
            unsafe { libc::_exit(0) };
        }

        // Parent: wait for child and inspect status.
        let mut wstatus: libc::c_int = 0;
        // SAFETY: pid is valid from fork.
        let ret = unsafe { libc::waitpid(pid, &mut wstatus, 0) };
        assert!(ret > 0, "waitpid failed");

        if libc::WIFEXITED(wstatus) {
            (true, libc::WEXITSTATUS(wstatus))
        } else if libc::WIFSIGNALED(wstatus) {
            (false, libc::WTERMSIG(wstatus))
        } else {
            panic!("unexpected wait status: {wstatus}");
        }
    }

    #[test]
    fn tier1_fspick_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            let path = b"/\0".as_ptr();
            // SAFETY: syscall with valid args.
            unsafe { libc::syscall(libc::SYS_fspick, libc::AT_FDCWD, path, 0) };
        });
        assert!(!exited, "child should be killed, not exit normally");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn tier2_execveat_empty_path_eperm() {
        let (exited, code) = run_in_filtered_child(|| {
            let empty = b"\0".as_ptr();
            // SAFETY: syscall with AT_EMPTY_PATH flag.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_execveat,
                    -1i32,
                    empty,
                    std::ptr::null::<*const libc::c_char>(),
                    std::ptr::null::<*const libc::c_char>(),
                    libc::AT_EMPTY_PATH,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno == libc::EPERM {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "expected EPERM (exit 42)");
    }

    #[test]
    fn tier2_socket_inet_eperm() {
        let (exited, code) = run_in_filtered_child(|| {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "expected EPERM (exit 42)");
    }

    #[test]
    fn tier2_socket_unix_allowed() {
        let (exited, code) = run_in_filtered_child(|| {
            let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                    libc::_exit(42);
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "AF_UNIX socket should be allowed");
    }

    #[test]
    fn tier1_unshare_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            // SAFETY: unshare with 0 flags is harmless but triggers the filter.
            unsafe { libc::unshare(0) };
        });
        assert!(!exited, "unshare should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn tier1_setns_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            // SAFETY: setns with invalid fd is harmless but triggers the filter.
            unsafe { libc::syscall(libc::SYS_setns, -1i32, 0i32) };
        });
        assert!(!exited, "setns should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn clone3_returns_enosys() {
        let (exited, code) = run_in_filtered_child(|| {
            // SAFETY: clone3 with NULL args returns EFAULT normally,
            // but our filter intercepts before the kernel checks args.
            let ret = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize) };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno == libc::ENOSYS {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "clone3 should return ENOSYS, not kill");
        assert_eq!(code, 42, "expected ENOSYS (exit 42)");
    }

    #[test]
    fn clone_thread_still_allowed() {
        let (exited, code) = run_in_filtered_child(|| {
            const STACK_SIZE: usize = 64 * 1024;
            let stack = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    STACK_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
                    -1,
                    0,
                )
            };
            if stack == libc::MAP_FAILED {
                unsafe { libc::_exit(2) };
            }
            let stack_top = unsafe { (stack as *mut u8).add(STACK_SIZE) };

            // CLONE_THREAD requires CLONE_SIGHAND which requires CLONE_VM.
            const FLAGS: libc::c_ulong = (libc::CLONE_THREAD
                | libc::CLONE_SIGHAND
                | libc::CLONE_VM
                | libc::CLONE_FS
                | libc::CLONE_FILES) as libc::c_ulong;

            // SAFETY: valid stack, thread immediately exits.
            extern "C" fn thread_fn(_arg: *mut libc::c_void) -> libc::c_int {
                0
            }

            let ret = unsafe {
                libc::clone(
                    thread_fn,
                    stack_top.cast(),
                    FLAGS as i32,
                    std::ptr::null_mut(),
                )
            };
            if ret > 0 {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        // The key assertion: seccomp did not kill the process (exited
        // normally, not via signal). clone() itself may fail on musl
        // (whose wrapper does not support CLONE_THREAD on x86_64), but
        // the seccomp filter must not be the reason.
        assert!(
            exited,
            "clone(CLONE_THREAD) should not be killed by seccomp"
        );
        assert!(
            code == 42 || code == 1,
            "expected exit 42 (clone ok) or 1 (clone failed, not killed): got {code}"
        );
    }

    #[test]
    fn clone_newuser_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            // SAFETY: clone with CLONE_NEWUSER and SIGCHLD, NULL stack
            // (kernel allocates). Will fail anyway but we just check the errno.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    libc::CLONE_NEWUSER | libc::SIGCHLD,
                    std::ptr::null::<u8>(),
                    std::ptr::null::<u8>(),
                    std::ptr::null::<u8>(),
                    0usize,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno == libc::EPERM {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "clone(CLONE_NEWUSER) should return EPERM, not kill");
        assert_eq!(code, 42, "expected EPERM (exit 42)");
    }

    #[test]
    fn clone_newnet_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    libc::CLONE_NEWNET | libc::SIGCHLD,
                    std::ptr::null::<u8>(),
                    std::ptr::null::<u8>(),
                    std::ptr::null::<u8>(),
                    0usize,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno == libc::EPERM {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "clone(CLONE_NEWNET) should return EPERM, not kill");
        assert_eq!(code, 42, "expected EPERM (exit 42)");
    }

    #[test]
    fn clone_combined_ns_thread_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            // Namespace flag takes precedence even combined with CLONE_THREAD.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    libc::CLONE_THREAD | libc::CLONE_NEWUSER | libc::SIGCHLD,
                    std::ptr::null::<u8>(),
                    std::ptr::null::<u8>(),
                    std::ptr::null::<u8>(),
                    0usize,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno == libc::EPERM {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(
            exited,
            "clone(CLONE_THREAD|CLONE_NEWUSER) should return EPERM"
        );
        assert_eq!(code, 42, "namespace flag should override thread flag");
    }

    #[test]
    fn execveat_without_empty_path_allowed() {
        let (exited, code) = run_in_filtered_child(|| {
            // execveat with flags=0 (no AT_EMPTY_PATH) should NOT be
            // blocked by seccomp. The null path causes EFAULT, not EPERM.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_execveat,
                    libc::AT_FDCWD,
                    std::ptr::null::<libc::c_char>(),
                    std::ptr::null::<*const libc::c_char>(),
                    std::ptr::null::<*const libc::c_char>(),
                    0i32,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno != libc::EPERM {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(
            code, 42,
            "execveat without AT_EMPTY_PATH should not be blocked"
        );
    }

    #[test]
    fn execveat_combined_flags_with_empty_path_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            // execveat with AT_EMPTY_PATH combined with other flags
            // should still be blocked by the MaskedEq filter.
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_execveat,
                    -1i32,
                    b"\0".as_ptr(),
                    std::ptr::null::<*const libc::c_char>(),
                    std::ptr::null::<*const libc::c_char>(),
                    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno == libc::EPERM {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(
            code, 42,
            "AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW should be blocked"
        );
    }

    #[test]
    fn tier1_quotactl_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            // SAFETY: quotactl with invalid args — triggers filter before kernel checks.
            unsafe { libc::syscall(libc::SYS_quotactl, 0i32, std::ptr::null::<u8>(), 0i32, 0u64) };
        });
        assert!(!exited, "quotactl should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn tier1_lsm_set_self_attr_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            // SAFETY: raw syscall with invalid args — filter kills before kernel processes.
            unsafe { libc::syscall(SYS_LSM_SET_SELF_ATTR, 0u64, 0u64, 0u64, 0u64) };
        });
        assert!(!exited, "lsm_set_self_attr should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn tier1_lsm_get_self_attr_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            // SAFETY: raw syscall with invalid args — filter kills before kernel processes.
            unsafe { libc::syscall(SYS_LSM_GET_SELF_ATTR, 0u64, 0u64, 0u64, 0u64) };
        });
        assert!(!exited, "lsm_get_self_attr should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn tier1_lsm_list_modules_kills() {
        let (exited, sig) = run_in_filtered_child(|| {
            // SAFETY: raw syscall with invalid args — filter kills before kernel processes.
            // x86_64/aarch64: __NR_lsm_list_modules = 461
            unsafe { libc::syscall(SYS_LSM_LIST_MODULES, 0u64, 0u64, 0u64) };
        });
        assert!(!exited, "lsm_list_modules should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from seccomp KILL");
    }

    #[test]
    fn prctl_pdeathsig_zero_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0) };
            if ret == -1 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "PR_SET_PDEATHSIG=0 should return EPERM");
    }

    #[test]
    fn prctl_set_dumpable_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
            if ret == -1 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "PR_SET_DUMPABLE=1 should return EPERM");
    }

    #[test]
    fn prctl_pdeathsig_sigkill_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
            if ret == -1 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "PR_SET_PDEATHSIG=SIGKILL should return EPERM");
    }

    #[test]
    fn prctl_pdeathsig_sigcont_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGCONT) };
            if ret == -1 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "PR_SET_PDEATHSIG=SIGCONT should return EPERM");
    }

    #[test]
    fn prctl_set_dumpable_two_blocked() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 2) };
            if ret == -1 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "PR_SET_DUMPABLE=2 should return EPERM");
    }

    #[test]
    fn prctl_set_dumpable_zero_allowed() {
        let (exited, code) = run_in_filtered_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
            if ret == 0 {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "PR_SET_DUMPABLE=0 should succeed");
    }

    #[test]
    fn tier2_socket_inet6_eperm() {
        let (exited, code) = run_in_filtered_child(|| {
            let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "AF_INET6 socket should return EPERM");
    }

    fn run_in_baseline_child(test_fn: fn()) -> (bool, i32) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            if let Err(e) = apply(&crate::SeccompProfile::Baseline) {
                eprintln!("seccomp baseline apply failed: {e}");
                unsafe { libc::_exit(99) };
            }
            test_fn();
            unsafe { libc::_exit(0) };
        }

        let mut wstatus: libc::c_int = 0;
        let ret = unsafe { libc::waitpid(pid, &mut wstatus, 0) };
        assert!(ret > 0, "waitpid failed");

        if libc::WIFEXITED(wstatus) {
            (true, libc::WEXITSTATUS(wstatus))
        } else if libc::WIFSIGNALED(wstatus) {
            (false, libc::WTERMSIG(wstatus))
        } else {
            panic!("unexpected wait status: {wstatus}");
        }
    }

    #[test]
    fn baseline_prctl_pdeathsig_blocked() {
        let (exited, code) = run_in_baseline_child(|| {
            let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0) };
            if ret == -1 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EPERM {
                    unsafe { libc::_exit(42) };
                }
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "baseline: PR_SET_PDEATHSIG should return EPERM");
    }

    #[test]
    fn baseline_io_uring_returns_enosys() {
        let (exited, code) = run_in_baseline_child(|| {
            let ret =
                unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, std::ptr::null::<u8>()) };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if ret < 0 && errno == libc::ENOSYS {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "io_uring_setup should return ENOSYS, not kill");
        assert_eq!(code, 42, "baseline: io_uring_setup should return ENOSYS");
    }

    #[test]
    fn x32_guard_builds() {
        let guard = build_x32_guard();
        #[cfg(target_arch = "x86_64")]
        {
            let prog = guard.expect("x32 guard should exist on x86_64");
            assert_eq!(prog.len(), 4, "x32 guard should be 4 BPF instructions");
        }
        #[cfg(not(target_arch = "x86_64"))]
        assert!(guard.is_none(), "x32 guard should be None on non-x86_64");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_tagged_syscall_kills() {
        // A syscall number with __X32_SYSCALL_BIT set should be killed
        // by the x32 guard, even if the native number is allowed.
        // Use SYS_getpid (native 39) ORed with 0x40000000.
        let (exited, sig) = run_in_filtered_child(|| unsafe {
            libc::syscall(0x4000_0000i64 | libc::SYS_getpid);
        });
        assert!(!exited, "x32-tagged syscall should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from x32 guard");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_guard_preserves_native_getpid() {
        // Native getpid (no x32 bit) must still work after the guard.
        let (exited, code) = run_in_filtered_child(|| {
            let pid = unsafe { libc::syscall(libc::SYS_getpid) };
            if pid > 0 {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "native getpid should not be killed");
        assert_eq!(code, 42, "native getpid should succeed");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_guard_baseline_kills() {
        // x32-tagged syscalls should also be killed in baseline profile.
        let (exited, sig) = run_in_baseline_child(|| unsafe {
            libc::syscall(0x4000_0000i64 | libc::SYS_getpid);
        });
        assert!(!exited, "baseline: x32-tagged syscall should be killed");
        assert_eq!(sig, libc::SIGSYS, "expected SIGSYS from x32 guard");
    }

    // ─── Retained-resource validation tests ─────────────────────
    //
    // All validation tests fork a child so the FD table scan is
    // isolated from parallel tests that may hold AF_UNIX sockets.

    /// Fork a child with a clean FD table, run `test_fn`, return
    /// (exited, exit_code_or_signal). Closes all FDs ≥ 3 in the
    /// child before calling `test_fn`, so parallel tests' sockets
    /// don't pollute the validation scan.
    fn run_in_clean_child(test_fn: fn()) -> (bool, i32) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Close inherited FDs from parallel tests.
            for fd in 3..1024 {
                unsafe { libc::close(fd) };
            }
            test_fn();
            unsafe { libc::_exit(0) };
        }
        let mut wstatus: libc::c_int = 0;
        let ret = unsafe { libc::waitpid(pid, &mut wstatus, 0) };
        assert!(ret > 0, "waitpid failed");
        if libc::WIFEXITED(wstatus) {
            (true, libc::WEXITSTATUS(wstatus))
        } else {
            (false, libc::WTERMSIG(wstatus))
        }
    }

    #[test]
    fn validate_no_retained_unix_resources_passes_clean() {
        let (exited, code) = run_in_clean_child(|| match validate_no_retained_unix_resources() {
            Ok(()) => unsafe { libc::_exit(42) },
            Err(_) => unsafe { libc::_exit(1) },
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "clean child should pass validation");
    }

    #[test]
    fn validate_rejects_inherited_unix_socket() {
        let (exited, code) = run_in_clean_child(|| {
            let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                unsafe { libc::_exit(99) };
            }
            match validate_no_retained_unix_resources() {
                Err(e) if e.to_string().contains("AF_UNIX") => {
                    unsafe { libc::close(fd) };
                    unsafe { libc::_exit(42) };
                }
                _ => {
                    unsafe { libc::close(fd) };
                    unsafe { libc::_exit(1) };
                }
            }
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "validation should reject AF_UNIX socket");
    }

    #[test]
    fn validate_accepts_inet_socket() {
        let (exited, code) = run_in_clean_child(|| {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                unsafe { libc::_exit(99) };
            }
            match validate_no_retained_unix_resources() {
                Ok(()) => {
                    unsafe { libc::close(fd) };
                    unsafe { libc::_exit(42) };
                }
                Err(_) => {
                    unsafe { libc::close(fd) };
                    unsafe { libc::_exit(1) };
                }
            }
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "AF_INET socket should be accepted");
    }

    #[test]
    fn validate_accepts_pipes() {
        let (exited, code) = run_in_clean_child(|| {
            let mut fds = [0i32; 2];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                unsafe { libc::_exit(99) };
            }
            match validate_no_retained_unix_resources() {
                Ok(()) => unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                    libc::_exit(42);
                },
                Err(_) => unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                    libc::_exit(1);
                },
            }
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "pipes should be accepted");
    }

    #[test]
    fn validate_deny_support_passes_on_supported() {
        // On the seccomp_supported cfg, this should succeed.
        let result = validate_deny_unix_sockets_support();
        if cfg!(seccomp_supported) {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn validate_single_threaded_passes() {
        // Cargo test may use threads, so fork a child to get a
        // guaranteed single-threaded context.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            match validate_single_threaded() {
                Ok(()) => unsafe { libc::_exit(42) },
                Err(_) => unsafe { libc::_exit(1) },
            }
        }
        let mut wstatus: libc::c_int = 0;
        let ret = unsafe { libc::waitpid(pid, &mut wstatus, 0) };
        assert!(ret > 0, "waitpid failed");
        assert!(libc::WIFEXITED(wstatus));
        assert_eq!(
            libc::WEXITSTATUS(wstatus),
            42,
            "single-threaded child should pass validation"
        );
    }

    #[test]
    fn baseline_prctl_set_name_allowed() {
        let (exited, code) = run_in_baseline_child(|| {
            let name = std::ffi::CString::new("test").unwrap();
            let ret = unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr()) };
            if ret == 0 {
                unsafe { libc::_exit(42) };
            }
            unsafe { libc::_exit(1) };
        });
        assert!(exited, "child should exit normally");
        assert_eq!(code, 42, "baseline: PR_SET_NAME should succeed");
    }
}
