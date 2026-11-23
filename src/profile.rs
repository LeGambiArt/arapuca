#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::Arc;

use crate::audit::{AuditSink, AuditVerbosity};

/// Isolation level for a sandboxed process.
#[derive(Debug, Clone, Default)]
pub enum Isolation {
    /// Process-level sandbox (Landlock, seccomp, cgroups, netns).
    #[default]
    Process,
    /// Micro-VM sandbox (libkrun). Strongest isolation — the
    /// subprocess runs inside a lightweight virtual machine with
    /// its own kernel. Requires the `microvm` feature.
    MicroVm(MicroVmConfig),
}

impl Isolation {
    /// Returns the image source if this is a MicroVm isolation.
    pub fn image_source(&self) -> Option<&ImageSource> {
        match self {
            Self::MicroVm(cfg) => Some(&cfg.image),
            Self::Process => None,
        }
    }
}

/// Configuration for micro-VM isolation.
///
/// No `Default` — the caller must explicitly choose the image,
/// CPU count, and memory allocation.
#[derive(Debug, Clone)]
pub struct MicroVmConfig {
    /// Image to boot.
    pub image: ImageSource,
    /// Number of vCPUs.
    pub cpus: u32,
    /// RAM in MB.
    pub mem_mb: u32,
    /// Files to inject into the guest via cloud-init write_files.
    /// Each entry: (guest_path, content, optional permissions).
    pub write_files: Vec<GuestFile>,
}

/// A file to inject into a micro-VM guest.
#[derive(Debug, Clone)]
pub struct GuestFile {
    /// Absolute path in the guest.
    pub path: String,
    /// File content.
    pub content: String,
    /// File permissions (e.g., "0644"). Defaults to "0644" if None.
    pub permissions: Option<String>,
}

/// Source for a micro-VM root filesystem image.
#[derive(Debug, Clone)]
pub enum ImageSource {
    /// Absolute path to a qcow2 file.
    Path(PathBuf),
    /// Distro specifier resolved via built-in or external providers.
    Distro { name: String, version: String },
}

/// Seccomp filter profile for the sandbox.
///
/// Controls the restrictiveness of the syscall filter applied to the
/// sandboxed process. The filter is applied by the arapuca wrapper
/// binary after Landlock and before execve.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SeccompProfile {
    /// Blocks AF_INET/AF_INET6 sockets, symlink, memfd_create,
    /// io_uring, pidfd, and other syscalls. Designed for untrusted
    /// code (scripts, build tools, agents).
    #[default]
    Strict,
    /// Blocks only sandbox-escape syscalls (ptrace, mount, namespace
    /// ops, kernel modules, bpf). Everything else is allowed.
    /// Designed for trusted-but-isolated applications (Claude Code,
    /// compilers) that need network sockets, memfd, io_uring, etc.
    /// Relies on Landlock + netns for the actual confinement.
    Baseline,
}

impl SeccompProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Baseline => "baseline",
        }
    }
}

/// Policy for cgroup resource limits when controllers aren't delegated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CgroupPolicy {
    /// Hard-fail if cgroups are unavailable and resource limits are
    /// requested. The sandbox refuses to launch.
    #[default]
    Required,
    /// Log a warning and continue with whatever cgroup controllers
    /// are delegated. Controllers that are unavailable are skipped.
    /// Landlock, seccomp, and namespace isolation still apply.
    /// Memory and PID limits require their respective cgroup
    /// controllers and cannot be enforced without them.
    BestEffort,
}

/// Filesystem and resource restrictions for a sandboxed process.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    /// Isolation level. Defaults to process-level sandbox.
    pub isolation: Isolation,
    /// Allowed read-only paths (canonicalized).
    pub read_paths: Vec<PathBuf>,
    /// Allowed read-write paths (canonicalized).
    pub write_paths: Vec<PathBuf>,
    /// Memory limit in MB (0 = no limit). Enforced via cgroups v2
    /// `memory.max` on Linux and RSS polling on macOS. u64 to
    /// support >4GB.
    pub max_memory_mb: u64,
    /// CPU percentage limit (0 = no limit; 200 = 2 cores).
    pub max_cpu_pct: u32,
    /// Maximum number of processes (0 = no limit). Enforced via
    /// cgroups v2 `pids.max` on Linux.
    pub max_pids: u32,
    /// Cgroup enforcement policy. Defaults to Required.
    pub cgroup_policy: CgroupPolicy,
    /// Hard CPU-time cap in seconds via RLIMIT_CPU (0 = no limit).
    /// Kills the process with SIGXCPU after this many seconds of
    /// cumulative CPU time (user + system). Independent of
    /// `max_cpu_pct` (proportional scheduling via cgroup `cpu.max`).
    pub cpu_timeout_secs: u64,
    /// Maximum file size in MB via RLIMIT_FSIZE (0 = no limit).
    pub max_file_size_mb: u64,
    /// Maximum open file descriptors via RLIMIT_NOFILE (0 = no limit).
    pub max_open_files: u64,
    /// Whether execve is permitted (for git, test runners, etc.).
    pub allow_exec: bool,
    /// Use CLONE_NEWNET for network namespace isolation (Linux only).
    pub use_netns: bool,
    /// Use CLONE_NEWPID for PID namespace isolation (Linux only).
    ///
    /// When enabled, the wrapper binary calls `unshare(CLONE_NEWPID)` +
    /// `fork()` so the target runs as PID 1 in an isolated namespace,
    /// unable to see or signal host processes. Requires a user namespace
    /// (provided by `use_netns`, or added automatically when `use_pidns`
    /// is true without `use_netns`).
    pub use_pidns: bool,
    /// Run under a user namespace with the current uid/gid mapped
    /// 1:1 (`unshare --user --map-current-user`). Linux only.
    ///
    /// An isolation-hardening layer, not an enforcement mechanism:
    /// the target is capless (mapping a non-root uid clears the
    /// namespace capabilities across exec), the host network is
    /// fully shared, and Yama ptrace coverage is unchanged (plain
    /// runs stay enforceable only at scopes 0/1). Never interacts
    /// with `use_netns`: the two are mutually exclusive, and this
    /// flag must not leak into network-namespace, bridge, or DNS
    /// eligibility anywhere.
    pub use_userns: bool,
    /// Enable DNS query capture inside the network namespace.
    ///
    /// When enabled, the bridge child runs a DNS server on UDP port 53
    /// that intercepts queries, logs them as `NetworkBlocked` audit
    /// events, and responds with NXDOMAIN.
    ///
    /// Requires `use_netns`, non-empty `read_paths` or `write_paths`
    /// (so the wrapper binary is invoked), and mount namespace support
    /// (`unshare --mount`). The `serde` Cargo feature is required for
    /// NDJSON parsing of audit events.
    pub dns_capture: bool,
    /// Opt the child out of the implicit "ALL APPLICATION PACKAGES" SID
    /// (Windows LPAC). Off by default: most non-Microsoft-signed binaries
    /// (and even some Microsoft ones, e.g. certutil.exe/whoami.exe) depend
    /// on registry keys/DLLs that were never ACL'd for the
    /// "ALL RESTRICTED APPLICATION PACKAGES" SID and fail to launch at all
    /// under LPAC (STATUS_DLL_INIT_FAILED/ACCESS_DENIED). AppContainer
    /// alone (without this) already denies filesystem access by default,
    /// which is the property that matters; LPAC only tightens read access
    /// to System32/Program Files (Microsoft-signed, non-attacker-controlled)
    /// and should stay opt-in until target binaries are verified compatible.
    /// No effect on non-Windows platforms.
    pub lpac: bool,
    /// Seccomp filter profile. Defaults to Strict.
    pub seccomp_profile: SeccompProfile,
    /// Deny Unix socket creation and retained Unix sockets/io_uring rings.
    /// Off by default; applies to both seccomp profiles. Supported only by
    /// Linux x86_64/aarch64 process isolation. Unsupported requests fail.
    /// Runtimes using Unix sockets or socketpairs may require this off.
    pub deny_unix_sockets: bool,
    /// Opt out of the PID namespace that a network-namespace launch
    /// implies. Inside a PID namespace, `kill(-1)` and pid-addressed
    /// signals only reach same-namespace processes, so the default
    /// couples the two; callers that genuinely need host-PID
    /// visibility set this. Exclusive with `use_pidns` (a profile
    /// combining both is a validation error).
    pub no_pid_ns: bool,
    /// Landlock signal scoping (Linux, kernel ABI 6+): the sandboxed
    /// process cannot send signals to processes outside its Landlock
    /// domain — closing `kill(-1, SIGKILL)` and friends against the
    /// supervising user's other processes.
    ///
    /// `None` (the default) derives from the seccomp profile: on with
    /// Strict, off with Baseline. `Some(v)` is explicit. On kernels
    /// below ABI 6 the scope is skipped with an audit event, never a
    /// failed run.
    pub scope_signals: Option<bool>,
    /// Deny filesystem-metadata mutation (chmod/chown/xattr/
    /// truncate class, including chattr ioctls) with seccomp EPERM.
    /// Landlock cannot restrict these on paths it otherwise grants,
    /// so without this tier a sandboxed process can `chmod 000
    /// ~/.ssh` or plant world-writable files on multi-user hosts.
    /// Every variant is denied, path-based and fd-based alike
    /// (`fchmod` works on `O_RDONLY` descriptors); only `ftruncate`
    /// survives, gated by Landlock write rights, and so does the
    /// timestamp family — GNU touch always utimensats after creating
    /// a file, and denying it breaks every build script that touches
    /// files. Creation modes (umask, O_CREAT) are likewise not
    /// covered.
    ///
    /// `None` (the default) derives from the seccomp profile: on
    /// with Strict, off with Baseline. `Some(v)` is explicit.
    pub deny_fs_metadata: Option<bool>,
    /// Selective Unix-socket connect policy (Linux process isolation
    /// only).
    ///
    /// `DenyPrivileged` (opt-in) brokers every `connect()` through the
    /// seccomp-unotify supervisor: connects to well-known privileged
    /// daemon sockets (docker, podman system, containerd, CRI-O, dbus
    /// system bus, libvirt, systemd manager, LXD, snapd) are denied
    /// with `EACCES`; everything else — including rootless daemon
    /// sockets under `/run/user/<uid>/` — keeps working. Landlock,
    /// seccomp, and network namespaces do not confine `connect()` to
    /// pathname Unix sockets, so without this policy a sandboxed
    /// process can drive a root-owned daemon (e.g. the docker daemon)
    /// and escape all confinement.
    ///
    /// Requires kernel ≥ 5.9 (seccomp `NOTIF_ADDFD`) and a supervisor
    /// that can inspect the target (a user namespace via `use_netns`/
    /// `use_pidns`, or Yama `ptrace_scope` = 0). When the policy is
    /// active but the supervisor cannot run, the launch fails — the
    /// target never runs unenforced.
    pub unix_socket_connect_policy: UnixSocketConnectPolicy,
    /// Extra deny roots for [`Profile::unix_socket_connect_policy`]:
    /// a connect is denied when the peer's bound path equals a root
    /// or lies beneath it. Merged with the built-in list. Paths must
    /// be absolute and must not contain `:` or `,` (environment
    /// encoding). Nonexistent roots are kept literal.
    pub unix_socket_deny_roots: Vec<PathBuf>,
    /// Opt-in: deny `connect()` to the same-user session daemons —
    /// the user's D-Bus (`/run/user/<uid>/bus`) and the systemd user
    /// manager (`/run/user/<uid>/systemd/private`). Without this,
    /// `systemd-run --user` from inside the sandbox starts a process
    /// outside every arapuca layer (Landlock, seccomp, cgroups); the
    /// built-in deny roots deliberately cover only root-owned
    /// daemons. Requires the unix socket connect policy.
    pub deny_user_session_sockets: bool,
    /// Audit file access via seccomp user notification.
    ///
    /// Intercepts `openat`/`openat2`/`open`/`execve` syscalls and emits
    /// `FileAccess` and `ProcessSpawn` audit events. The syscalls are
    /// always allowed through — this is observation only.
    ///
    /// Requires kernel ≥ 5.5 (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`).
    /// Silently skipped on older kernels or when Yama `ptrace_scope`
    /// blocks cross-process `/proc/<pid>/mem` access (unless a user
    /// namespace is active via `use_netns` or `use_pidns`).
    pub audit_file_access: bool,
    /// Audit network connections via seccomp user notification.
    ///
    /// Intercepts `connect`/`sendto`/`sendmsg`/`sendmmsg` syscalls.
    /// When `use_netns` is active, allows connections to the bridge
    /// address and blocks all other INET connections with ECONNREFUSED.
    /// When `use_netns` is not active, logs connections without blocking.
    ///
    /// Requires kernel ≥ 5.5. Same Yama constraints as `audit_file_access`.
    pub audit_network: bool,
    /// Switch child process seccomp filters to debug mode.
    ///
    /// When enabled, internal child processes (bridge, connect proxy,
    /// unotify supervisor) use `SECCOMP_RET_TRAP` instead of
    /// `SECCOMP_RET_KILL_PROCESS`, with a SIGSYS handler that prints
    /// blocked syscall names to stderr. Does NOT affect the main
    /// sandbox filter protecting the untrusted process.
    pub seccomp_debug: bool,
    /// Forward standard HTTP(S) proxy environment variables from the
    /// launching process to the sandboxed process.
    ///
    /// The caller-env filter normally strips `HTTP_PROXY`/`HTTPS_PROXY`/
    /// `NO_PROXY` (and lowercase/`ALL_PROXY` variants) because an
    /// attacker-influenced proxy could redirect or MITM the sandboxed
    /// process's traffic. When true, the launcher instead injects those
    /// variables from its OWN environment (a trusted operator source),
    /// bypassing the filter, so tools that must reach the network
    /// through a local proxy work in baseline network mode.
    ///
    /// Only meaningful when outbound network is allowed (macOS baseline
    /// seccomp mode). Ignored on other platforms.
    pub allow_proxy_env: bool,
    /// Grant the sandboxed process access to the macOS Keychain
    /// (macOS only; ignored on other platforms).
    ///
    /// The deny-default Seatbelt profile blocks the Mach services and
    /// files that `Security.framework` needs to read Keychain items,
    /// so tools that authenticate via the login Keychain (e.g. stored
    /// OAuth tokens) report "not logged in" inside the
    /// sandbox. When true, the profile additionally allows the
    /// `securityd`/`trustd` Mach lookups and read access to the
    /// Keychain database files so native Keychain authentication works.
    ///
    /// On macOS this also points `HOME` at the launching user's real home
    /// directory (the Keychain search list is derived from `HOME`; the
    /// sandbox's default temp `HOME` omits the login keychain, so items
    /// cannot be found otherwise). Confinement is unaffected — the mount
    /// profile, not `$HOME`, bounds what is accessible.
    ///
    /// This widens the sandbox: the process can read any Keychain item
    /// the invoking user can. Enable only for trusted tools that need
    /// Keychain-backed credentials.
    pub allow_keychain: bool,
    /// Additional exact macOS Mach service names allowed for XPC lookup.
    ///
    /// Empty by default. Each entry grants only `mach-lookup` for that exact
    /// global service name; no wildcard matching is supported.
    pub mach_lookup_services: Vec<String>,
    /// Allow the process to bind and accept TCP connections.
    ///
    /// Off by default. Seatbelt's network address filters do not provide a
    /// reliable loopback-only bind/inbound boundary: the `localhost` matcher
    /// can also permit wildcard binds. Enable only for trusted applications
    /// that need a local listener. On Linux this enables an isolated network
    /// namespace with loopback up and baseline seccomp so listeners remain
    /// confined to that namespace.
    pub allow_network_listeners: bool,
}

impl Profile {
    /// Effective signal-scoping request: `None` follows the seccomp
    /// profile (Strict locks it on, Baseline leaves it off), an
    /// explicit value wins. Computed where the real profile lives —
    /// the launcher — never in the wrapper, whose reconstructed
    /// profile always reads as Strict.
    pub fn effective_scope_signals(&self) -> bool {
        self.scope_signals
            .unwrap_or(self.seccomp_profile == SeccompProfile::Strict)
    }

    /// Effective metadata-denial request, same derivation rule as
    /// [`Profile::effective_scope_signals`].
    pub fn effective_deny_fs_metadata(&self) -> bool {
        self.deny_fs_metadata
            .unwrap_or(self.seccomp_profile == SeccompProfile::Strict)
    }

    /// Validate the PID-namespace opt-out: it is meaningless (and
    /// ambiguous) alongside an explicit `use_pidns`, so fail closed
    /// on the combination instead of guessing which one wins.
    pub fn validate_pidns(&self) -> crate::Result<()> {
        if self.no_pid_ns && self.use_pidns {
            return Err(crate::Error::Validation(
                "no_pid_ns is exclusive with use_pidns: pick one".into(),
            ));
        }
        Ok(())
    }

    /// Validate the `use_userns` combination rules.
    ///
    /// Fail-closed on ambiguous requests rather than choosing a
    /// mapping: the netns-implying modes already create a user
    /// namespace with a root mapping, and PID namespaces require
    /// the netns launch shape. Called by the CLI and the launcher;
    /// the launcher additionally rejects a user namespace requested
    /// alongside a network proxy (a `Config`-level field).
    pub fn validate_userns(&self) -> crate::Result<()> {
        if !self.use_userns {
            return Ok(());
        }
        if !cfg!(target_os = "linux") {
            return Err(crate::Error::Validation("--userns requires Linux".into()));
        }
        if self.use_netns || self.use_pidns {
            return Err(crate::Error::Validation(
                "--userns is exclusive with the network-namespace modes \
                 (--deny-network, --allow-host, --allow-network-listeners, \
                 --proxy-socket) and with --pid namespaces"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Validate exact Mach service names used for macOS XPC lookup grants.
    ///
    /// A leading hyphen is rejected so that a mistyped `--allow-xpc
    /// --deny-network` cannot silently consume a flag as the service name.
    /// No real macOS Mach service name begins with a hyphen.
    pub fn validate_mach_lookup_services(&self) -> crate::Result<()> {
        for service in &self.mach_lookup_services {
            let valid_chars = service.chars().all(|ch| {
                ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ' ' | '(' | ')')
            });
            if service.is_empty()
                || service.len() > 255
                || service.trim() != service
                || service.starts_with('-')
                || !valid_chars
            {
                return Err(crate::Error::Validation(format!(
                    "invalid Mach service name {service:?}; expected 1-255 ASCII letters, \
                     digits, dots, underscores, hyphens, spaces, or parentheses, not starting \
                     with a hyphen"
                )));
            }
        }
        Ok(())
    }

    /// Validate availability of an explicitly requested Unix socket policy.
    pub fn validate_unix_socket_policy(&self) -> crate::Result<()> {
        if self.deny_unix_sockets
            && (!cfg!(seccomp_supported) || !matches!(self.isolation, Isolation::Process))
        {
            return Err(crate::Error::Validation(
                "Unix socket denial requires Linux x86_64/aarch64 process isolation".into(),
            ));
        }
        self.validate_unix_connect_policy()
    }

    /// Validate the Unix socket connect policy and its deny roots.
    ///
    /// Fail-closed: an explicitly requested `DenyPrivileged` policy on
    /// an unsupported platform/isolation is an error, never a silent
    /// no-op, and explicitly configured deny roots are rejected where
    /// they cannot be enforced (including MicroVm, where host sockets
    /// are unreachable and the roots would be silently dropped).
    fn validate_unix_connect_policy(&self) -> crate::Result<()> {
        use std::fmt::Write as _;

        let policy_active =
            self.unix_socket_connect_policy == UnixSocketConnectPolicy::DenyPrivileged;
        let roots_explicit =
            !self.unix_socket_deny_roots.is_empty() || self.deny_user_session_sockets;

        if policy_active
            && (!cfg!(seccomp_supported) || !matches!(self.isolation, Isolation::Process))
        {
            let mut msg = String::from(
                "unix socket connect policy requires \
                 Linux x86_64/aarch64 process isolation",
            );
            if !cfg!(seccomp_supported) {
                let _ = write!(msg, "; opt out with unix_socket_connect_policy = AllowAll");
            }
            return Err(crate::Error::Validation(msg));
        }
        if roots_explicit && !policy_active {
            return Err(crate::Error::Validation(
                "unix_socket_deny_roots requires \
                 unix_socket_connect_policy = DenyPrivileged"
                    .into(),
            ));
        }
        for root in &self.unix_socket_deny_roots {
            if root.as_os_str().is_empty() {
                return Err(crate::Error::Validation(
                    "unix socket deny root was not a valid path \
                     (NULL or non-UTF-8 from the caller)"
                        .into(),
                ));
            }
            if !root.is_absolute() {
                return Err(crate::Error::Validation(format!(
                    "unix socket deny root must be absolute: {}",
                    root.display()
                )));
            }
            let s = root.to_string_lossy();
            if s.contains(':') || s.contains(',') {
                return Err(crate::Error::Validation(format!(
                    "unix socket deny root must not contain ':' or ',': {s}"
                )));
            }
        }
        Ok(())
    }
}

/// Selective Unix-socket connect policy. See
/// [`Profile::unix_socket_connect_policy`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnixSocketConnectPolicy {
    /// Broker `connect()` and deny privileged daemon sockets.
    DenyPrivileged,
    /// Legacy behavior: no connect() brokering.
    #[default]
    AllowAll,
}

#[cfg(test)]
mod unix_policy_tests {
    use super::*;

    #[test]
    fn explicitly_requested_policy_requires_a_supported_backend() {
        let mut profile = Profile::default();
        assert!(profile.validate_unix_socket_policy().is_ok());
        profile.deny_unix_sockets = true;
        assert_eq!(
            profile.validate_unix_socket_policy().is_ok(),
            cfg!(seccomp_supported)
        );
        profile.isolation = Isolation::MicroVm(MicroVmConfig {
            image: ImageSource::Path(PathBuf::from("/unused")),
            cpus: 1,
            mem_mb: 128,
            write_files: vec![],
        });
        assert!(profile.validate_unix_socket_policy().is_err());
    }

    #[test]
    fn mach_lookup_services_are_exact_safe_names() {
        let mut profile = Profile::default();
        profile.mach_lookup_services = vec!["mul-xpc (Apple)_OpenStep".into()];
        assert!(profile.validate_mach_lookup_services().is_ok());

        profile.mach_lookup_services = vec!["service\") (allow default) (deny nothing \"".into()];
        assert!(profile.validate_mach_lookup_services().is_err());
        profile.mach_lookup_services = vec!["com.apple.*".into()];
        assert!(profile.validate_mach_lookup_services().is_err());
        // A flag swallowed as a service name must not pass validation.
        profile.mach_lookup_services = vec!["--deny-network".into()];
        assert!(profile.validate_mach_lookup_services().is_err());
    }
}

/// Full configuration for launching a sandboxed process.
#[derive(Clone)]
pub struct Config {
    /// Security restrictions to apply.
    pub profile: Profile,
    /// Per-agent socket directory (created via tempdir, mode 0700).
    pub socket_dir: PathBuf,
    /// Task identifier. Validated: ^[a-zA-Z0-9-]+$, max 128 chars.
    pub task_id: String,
    /// Current phase (opaque to arapuca — passed through to caller).
    pub phase: String,
    /// Working directory for the subprocess (None = inherit).
    pub work_dir: Option<PathBuf>,
    /// Redirect subprocess stdin from this FD (None = inherit).
    #[cfg(unix)]
    pub stdin: Option<RawFd>,
    /// Redirect subprocess stdout to this FD (None = inherit).
    #[cfg(unix)]
    pub stdout: Option<RawFd>,
    /// Redirect subprocess stderr to this FD (None = inherit).
    #[cfg(unix)]
    pub stderr: Option<RawFd>,
    /// Additional FDs to inherit to the subprocess.
    #[cfg(unix)]
    pub extra_fds: Vec<RawFd>,
    /// Allocate a PTY pair and attach the slave as the child's
    /// controlling terminal. Incompatible with stdin/stdout/stderr
    /// redirection.
    #[cfg(unix)]
    pub tty: bool,
    /// Path to the network proxy Unix socket. When set, the subprocess
    /// receives an env var pointing to this socket. Uses a non-ARAPUCA
    /// prefix so it is not stripped by the binary.
    pub network_proxy_socket: Option<PathBuf>,
    /// Allowed outbound host:port pairs for the CONNECT proxy.
    /// When non-empty, `Launch()` forks a CONNECT proxy (like `--allow-host`
    /// in the CLI), sets `network_proxy_socket` to the proxy socket path,
    /// and enables network namespace isolation automatically.
    /// Linux only.
    #[cfg(target_os = "linux")]
    pub allowed_hosts: Vec<crate::bridge::AllowedHost>,
    /// Caller-supplied environment variables for the subprocess.
    /// Filtered by the platform launcher before use: ARAPUCA_*,
    /// LD_*, DYLD_*, and other dangerous names are silently dropped.
    /// Callers should not provide duplicate keys. On Windows, entries are
    /// sorted case-insensitively and process lookup uses the first matching
    /// entry. Launcher-managed keys are removed and re-added so sandbox
    /// values take precedence.
    pub env: Vec<(String, String)>,
    /// Optional audit event sink. When None, no events are emitted
    /// and zero audit overhead is incurred.
    pub audit_sink: Option<Arc<dyn AuditSink>>,
    /// Controls how much detail audit events include.
    pub audit_verbosity: AuditVerbosity,
    /// Caller-supplied principal identity for audit records.
    pub audit_principal: Option<String>,
    /// Caller-supplied correlation ID for distributed tracing.
    pub audit_correlation_id: Option<String>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Config");
        s.field("profile", &self.profile)
            .field("socket_dir", &self.socket_dir)
            .field("task_id", &self.task_id)
            .field("phase", &self.phase)
            .field("work_dir", &self.work_dir);
        #[cfg(unix)]
        {
            s.field("stdin", &self.stdin)
                .field("stdout", &self.stdout)
                .field("stderr", &self.stderr)
                .field("extra_fds", &self.extra_fds)
                .field("tty", &self.tty);
        }
        s.field("network_proxy_socket", &self.network_proxy_socket);
        #[cfg(target_os = "linux")]
        s.field(
            "allowed_hosts",
            &format!("[{} hosts]", self.allowed_hosts.len()),
        );
        s.field("env", &format!("[{} vars]", self.env.len()))
            .field(
                "audit_sink",
                if self.audit_sink.is_some() {
                    &"Some(<AuditSink>)"
                } else {
                    &"None"
                },
            )
            .field("audit_verbosity", &self.audit_verbosity)
            .field("audit_principal", &self.audit_principal)
            .field("audit_correlation_id", &self.audit_correlation_id)
            .finish()
    }
}

/// Resource usage statistics from cgroups v2.
///
/// All fields are best-effort — they return zero if the corresponding
/// cgroup controller is unavailable or the stat file is unreadable.
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    /// Current memory usage in bytes.
    pub memory_current_bytes: i64,
    /// Peak memory usage in bytes (kernel 5.19+).
    pub memory_peak_bytes: i64,
    /// Total CPU time consumed in seconds.
    pub cpu_usage_seconds: f64,
    /// Number of processes in the cgroup.
    pub pid_count: i64,
    /// Total I/O bytes read (summed across all devices).
    pub io_read_bytes: i64,
    /// Total I/O bytes written (summed across all devices).
    pub io_write_bytes: i64,
}

#[cfg(all(test, target_os = "linux"))]
mod userns_tests {
    use super::*;

    #[test]
    fn userns_valid_without_conflicts() {
        let mut profile = Profile::default();
        assert!(profile.validate_userns().is_ok());
        profile.use_userns = true;
        assert!(profile.validate_userns().is_ok());
    }

    #[test]
    fn userns_rejects_netns_and_pidns_combinations() {
        let mut profile = Profile::default();
        profile.use_userns = true;
        profile.use_netns = true;
        assert!(profile.validate_userns().is_err());
        profile.use_netns = false;
        profile.use_pidns = true;
        assert!(profile.validate_userns().is_err());
        profile.use_pidns = false;
        assert!(profile.validate_userns().is_ok());
    }
}

#[cfg(test)]
mod scope_signals_tests {
    use super::*;

    #[test]
    fn scope_signals_derives_from_seccomp_profile() {
        let mut p = Profile::default();
        assert_eq!(p.seccomp_profile, SeccompProfile::Strict);
        assert!(p.effective_scope_signals(), "Strict default locks it on");

        p.seccomp_profile = SeccompProfile::Baseline;
        assert!(!p.effective_scope_signals(), "Baseline leaves it off");

        p.scope_signals = Some(true);
        assert!(p.effective_scope_signals(), "explicit Some(true) wins");

        p.scope_signals = Some(false);
        assert!(!p.effective_scope_signals(), "explicit Some(false) wins");
    }
}

#[cfg(test)]
mod pidns_coupling_tests {
    use super::*;

    #[test]
    fn no_pid_ns_is_exclusive_with_use_pidns() {
        let p = Profile {
            no_pid_ns: true,
            use_pidns: true,
            ..Default::default()
        };
        let err = p.validate_pidns().expect_err("combination must fail");
        assert!(err.to_string().contains("exclusive"), "unexpected: {err}");

        let ok = Profile {
            no_pid_ns: true,
            ..Default::default()
        };
        assert!(ok.validate_pidns().is_ok());
    }
}
