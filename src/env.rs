//! Environment and directory utilities for sandboxed processes.
//!
//! Provides functions for constructing minimal environments, creating
//! temp directories, socket directories, and canonicalizing paths.

use std::path::{Path, PathBuf};

use crate::audit::{DropReason, DroppedEnvVar};

/// Construct a minimal environment for a sandboxed subprocess.
///
/// Only includes HOME, TMPDIR, PATH, and LANG. This prevents
/// information leakage from the host environment to the agent.
pub fn minimal_env(tmp_dir: &Path) -> Vec<(String, String)> {
    vec![
        ("HOME".into(), tmp_dir.to_string_lossy().into_owned()),
        ("TMPDIR".into(), tmp_dir.to_string_lossy().into_owned()),
        (
            "PATH".into(),
            "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin".into(),
        ),
        ("LANG".into(), "C.UTF-8".into()),
    ]
}

/// Result of filtering caller-supplied environment variables.
pub struct FilterResult {
    /// Variables that passed the filter.
    pub passed: Vec<(String, String)>,
    /// Variables that were dropped, with the reason for each.
    pub dropped: Vec<DroppedEnvVar>,
}

/// Filter caller-supplied env vars, dropping dangerous entries.
///
/// Drops vars that could subvert sandbox confinement:
/// - `ARAPUCA_*` — sandbox config re-injection
/// - `AGENT_NETWORK_PROXY` — set by launcher, not caller
/// - `LD_*`, `DYLD_*` — dynamic linker injection
/// - `COR_*`, `CORECLR_*`, `DOTNET_*`, `COMPLUS_*` — .NET profiler/runtime injection
/// - `__COMPAT_LAYER` — Windows compatibility shim injection
/// - Interpreter injection: `BASH_ENV`, `ENV`, `PYTHONPATH`,
///   `PYTHONSTARTUP`, `NODE_OPTIONS`, `PERL5OPT`, `PERL5LIB`
/// - `COMSPEC`, `PSModulePath`, `PATHEXT` — Windows shell/exec injection
pub fn filter_caller_env(env: &[(String, String)]) -> FilterResult {
    let mut passed = Vec::new();
    let mut dropped = Vec::new();

    for (k, v) in env {
        if let Some(reason) = drop_reason(k) {
            dropped.push(DroppedEnvVar {
                key: k.clone(),
                reason,
            });
        } else {
            passed.push((k.clone(), v.clone()));
        }
    }

    FilterResult { passed, dropped }
}

pub fn drop_reason(key: &str) -> Option<DropReason> {
    if key.starts_with("ARAPUCA_") {
        return Some(DropReason::ArapucaPrefix);
    }
    if key == "AGENT_NETWORK_PROXY" {
        return Some(DropReason::LauncherReserved);
    }
    if key.starts_with("LD_") {
        return Some(DropReason::LdPrefix);
    }
    if key.starts_with("DYLD_") {
        return Some(DropReason::DyldPrefix);
    }
    if key.starts_with("COR_")
        || key.starts_with("CORECLR_")
        || key.starts_with("DOTNET_")
        || key.starts_with("COMPLUS_")
    {
        return Some(DropReason::DotnetPrefix);
    }
    if key == "__COMPAT_LAYER" {
        return Some(DropReason::WindowsShimInjection);
    }
    if matches!(
        key,
        "BASH_ENV"
            | "ENV"
            | "PYTHONPATH"
            | "PYTHONSTARTUP"
            | "NODE_OPTIONS"
            | "PERL5OPT"
            | "PERL5LIB"
            | "ZDOTDIR"
            | "IFS"
            | "PROMPT_COMMAND"
    ) {
        return Some(DropReason::InterpreterInjection);
    }
    if matches!(key, "COMSPEC" | "PSModulePath" | "PATHEXT") {
        return Some(DropReason::ShellInjection);
    }
    if matches!(
        key,
        "GCONV_PATH" | "HOSTALIASES" | "LOCPATH" | "GETCONF_DIR"
    ) {
        return Some(DropReason::RuntimeInjection);
    }
    if matches!(
        key,
        "RUBYOPT"
            | "RUBYLIB"
            | "JAVA_TOOL_OPTIONS"
            | "_JAVA_OPTIONS"
            | "CLASSPATH"
            | "PYTHONHOME"
            | "GOFLAGS"
            | "GIT_CONFIG_GLOBAL"
            | "GIT_CONFIG_SYSTEM"
            | "GIT_SSH_COMMAND"
            | "GIT_SSH"
            | "GIT_EXEC_PATH"
            | "GIT_TEMPLATE_DIR"
            | "GIT_EXTERNAL_DIFF"
            | "GIT_ASKPASS"
            | "GIT_EDITOR"
            | "GIT_SEQUENCE_EDITOR"
            | "OPENSSL_CONF"
            | "EDITOR"
            | "VISUAL"
            | "PAGER"
            | "CARGO_HOME"
    ) {
        return Some(DropReason::RuntimeInjection);
    }
    if matches!(
        key,
        "http_proxy"
            | "HTTP_PROXY"
            | "https_proxy"
            | "HTTPS_PROXY"
            | "ALL_PROXY"
            | "all_proxy"
            | "NO_PROXY"
            | "no_proxy"
            | "ftp_proxy"
            | "FTP_PROXY"
            | "SOCKS_PROXY"
            | "socks_proxy"
            | "CGI_HTTP_PROXY"
            | "CURL_CA_BUNDLE"
            | "SSL_CERT_FILE"
            | "SSL_CERT_DIR"
            | "REQUESTS_CA_BUNDLE"
    ) {
        return Some(DropReason::RuntimeInjection);
    }
    None
}

/// Create a temporary directory for the sandbox.
///
/// The directory is created under the system temp dir with a random
/// suffix to prevent symlink attacks and directory squatting.
pub fn make_tmp_dir(task_id: &str) -> crate::Result<PathBuf> {
    let prefix = format!("arapuca-{task_id}-");
    let dir = make_temp_dir(&prefix)?;
    Ok(dir)
}

/// RAII guard that removes a temporary directory on drop unless defused.
///
/// Used to prevent tmpdir leaks on early error returns between
/// `make_tmp_dir()` and successful `Process` construction.
#[cfg(unix)]
pub(crate) struct TmpDirGuard {
    path: std::path::PathBuf,
    active: bool,
}

#[cfg(unix)]
impl TmpDirGuard {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path, active: true }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn defuse(mut self) -> std::path::PathBuf {
        self.active = false;
        std::mem::take(&mut self.path)
    }
}

#[cfg(unix)]
impl Drop for TmpDirGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Create a socket directory for JSON-RPC communication.
///
/// Creates a directory with mode 0700 and a random suffix for the
/// control and LLM sockets.
pub fn make_socket_dir() -> crate::Result<PathBuf> {
    make_temp_dir("arapuca-sock-")
}

/// Canonicalize a list of paths, resolving symlinks and making them absolute.
///
/// Prevents symlink escape attacks where a crafted symlink inside a
/// writable path points outside it. For paths that don't exist, falls
/// back to canonicalizing the parent directory + the final component
/// (matching Go's behavior). Returns empty vec only if all paths fail.
pub fn canonicalize_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .filter_map(|p| {
            // Try direct canonicalization first.
            if let Ok(canon) = std::fs::canonicalize(p) {
                return Some(canon);
            }
            // Fallback: canonicalize parent + append basename.
            let parent = p.parent()?;
            let name = p.file_name()?;
            let canon_parent = std::fs::canonicalize(parent).ok()?;
            Some(canon_parent.join(name))
        })
        .collect()
}

/// Platform-specific path list separator.
///
/// `:` on Unix, `;` on Windows (where `:` appears in drive letters).
const PATH_LIST_SEP: char = if cfg!(windows) { ';' } else { ':' };

/// Parse paths from a separator-delimited string.
///
/// Used by the binary to parse ARAPUCA_READ_PATHS and ARAPUCA_WRITE_PATHS
/// environment variables. Uses `:` on Unix, `;` on Windows.
pub fn parse_paths(s: &str) -> Vec<PathBuf> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(PATH_LIST_SEP)
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Binary name for the arapuca wrapper.
const WRAPPER_BIN: &str = if cfg!(windows) {
    "arapuca.exe"
} else {
    "arapuca"
};

/// Returns the path to the arapuca wrapper binary if it exists.
///
/// When selfexec mode is enabled, returns the current executable
/// (the consumer binary acts as its own wrapper). Otherwise looks
/// next to the current executable, then in PATH.
pub fn wrapper_path() -> Option<PathBuf> {
    if crate::selfexec::selfexec_enabled() {
        match std::env::current_exe() {
            Ok(exe) => return Some(exe),
            Err(e) => {
                log::warn!("selfexec: current_exe() failed: {e}");
                return None;
            }
        }
    }
    // Look next to the current executable, then one level up
    // (handles cargo test binaries in target/debug/deps/).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(WRAPPER_BIN);
            if candidate.is_file() {
                return Some(candidate);
            }
            if let Some(parent) = dir.parent() {
                let candidate = parent.join(WRAPPER_BIN);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    // Fall back to PATH.
    for dir in std::env::var("PATH")
        .unwrap_or_default()
        .split(PATH_LIST_SEP)
    {
        let candidate = PathBuf::from(dir).join(WRAPPER_BIN);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Build environment variables for the arapuca wrapper binary.
///
/// These configure Landlock paths and rlimits. Uses the `ARAPUCA_*`
/// prefix so the wrapper strips them after applying.
pub fn wrapper_env(profile: &crate::Profile) -> crate::Result<Vec<(String, String)>> {
    let sep_char = PATH_LIST_SEP;
    for path in profile.read_paths.iter().chain(profile.write_paths.iter()) {
        let s = path.to_string_lossy();
        if s.contains(sep_char) {
            return Err(crate::Error::Validation(format!(
                "sandbox path must not contain '{sep_char}': {s}"
            )));
        }
    }

    let mut env = Vec::new();
    env.push(("ARAPUCA_WRAPPER".into(), "1".into()));
    if !profile.read_paths.is_empty() {
        let paths: Vec<String> = profile
            .read_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let sep = &sep_char.to_string();
        env.push(("ARAPUCA_READ_PATHS".into(), paths.join(sep)));
    }
    if !profile.write_paths.is_empty() {
        let paths: Vec<String> = profile
            .write_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let sep = &sep_char.to_string();
        env.push(("ARAPUCA_WRITE_PATHS".into(), paths.join(sep)));
    }
    if profile.max_file_size_mb > 0 {
        env.push((
            "ARAPUCA_RLIMIT_FSIZE".into(),
            profile
                .max_file_size_mb
                .saturating_mul(1024 * 1024)
                .to_string(),
        ));
    }
    if profile.max_open_files > 0 {
        env.push((
            "ARAPUCA_RLIMIT_NOFILE".into(),
            profile.max_open_files.to_string(),
        ));
    }
    if profile.cpu_timeout_secs > 0 {
        env.push((
            "ARAPUCA_RLIMIT_CPU".into(),
            profile.cpu_timeout_secs.to_string(),
        ));
    }
    // Always emit — never rely on absence encoding a default.
    // Linux::launch() calls env_clear() so ambient vars don't leak,
    // but defense-in-depth: explicit is better than implicit.
    env.push((
        "ARAPUCA_SECCOMP_PROFILE".into(),
        profile.seccomp_profile.as_str().into(),
    ));
    env.push((
        "ARAPUCA_ALLOW_EXEC".into(),
        if profile.allow_exec { "1" } else { "0" }.into(),
    ));
    env.push((
        "ARAPUCA_DENY_UNIX_SOCKETS".into(),
        if profile.deny_unix_sockets { "1" } else { "0" }.into(),
    ));
    if profile.seccomp_debug {
        env.push(("ARAPUCA_SECCOMP_DEBUG".into(), "1".into()));
    }
    Ok(env)
}

/// Fixed port for the proxy bridge TCP listener. The bridge runs
/// inside an isolated network namespace where port conflicts are
/// impossible. Used by both `bridge_env()` and the audit layer.
pub const BRIDGE_PORT: u16 = 18080;

/// Build the `ARAPUCA_PROXY_BRIDGE` env var for the wrapper binary.
///
/// Returns `Some((key, value))` when both `use_netns` is true and
/// `proxy_socket` is set. The value format is `<port>:<socket_path>`.
/// Returns `None` if the bridge should not be activated, or an error
/// if the socket path contains a colon (which would break parsing).
pub fn bridge_env(
    use_netns: bool,
    proxy_socket: Option<&std::path::Path>,
) -> crate::Result<Option<(String, String)>> {
    let Some(socket) = proxy_socket else {
        return Ok(None);
    };
    if !use_netns {
        return Ok(None);
    }

    let socket_str = socket.to_string_lossy();
    if socket_str.contains(':') {
        return Err(crate::Error::Validation(format!(
            "proxy socket path must not contain colons: {socket_str}"
        )));
    }

    Ok(Some((
        "ARAPUCA_PROXY_BRIDGE".into(),
        format!("{BRIDGE_PORT}:{socket_str}"),
    )))
}

/// Build the `ARAPUCA_UNOTIFY_CONFIG` env var for the wrapper binary.
///
/// Encodes which unotify audit features are enabled and the bridge port
/// for network enforcement. Format: comma-separated flags.
pub fn unotify_env(profile: &crate::Profile) -> Option<(String, String)> {
    if !profile.audit_file_access && !profile.audit_network {
        return None;
    }
    let mut parts = Vec::new();
    if profile.audit_file_access {
        parts.push("file".to_string());
    }
    if profile.audit_network {
        parts.push("network".to_string());
        if profile.use_netns {
            parts.push(format!("bridge_port={BRIDGE_PORT}"));
            parts.push("enforce".to_string());
        }
    }
    if profile.dns_capture && profile.use_netns {
        parts.push("dns_port=53".to_string());
    }
    Some(("ARAPUCA_UNOTIFY_CONFIG".into(), parts.join(",")))
}

/// Parse the `ARAPUCA_UNOTIFY_CONFIG` env var in the wrapper binary.
#[cfg(seccomp_supported)]
pub fn parse_unotify_config() -> Option<crate::unotify::UnotifyConfig> {
    let val = std::env::var("ARAPUCA_UNOTIFY_CONFIG").ok()?;
    let mut audit_file_access = false;
    let mut audit_network = false;
    let mut bridge_port = None;
    let mut dns_port = None;
    let mut enforce_network = false;

    for part in val.split(',') {
        match part {
            "file" => audit_file_access = true,
            "network" => audit_network = true,
            "enforce" => enforce_network = true,
            s if s.starts_with("bridge_port=") => {
                bridge_port = s.strip_prefix("bridge_port=").and_then(|p| p.parse().ok());
            }
            s if s.starts_with("dns_port=") => {
                dns_port = s.strip_prefix("dns_port=").and_then(|p| p.parse().ok());
            }
            _ => {}
        }
    }

    if !audit_file_access && !audit_network {
        return None;
    }

    Some(crate::unotify::UnotifyConfig {
        audit_file_access,
        audit_network,
        bridge_port,
        dns_port,
        enforce_network,
    })
}

/// Per-platform default read and write paths for `arapuca run`.
///
/// Returns `(read_paths, write_paths)` with the minimal filesystem
/// access a sandboxed process needs to function. Follows the container
/// runtime model: curated specific entries, not blanket virtual
/// filesystem trees.
///
/// # Security
///
/// These defaults define the sandbox attack surface. Adding paths here
/// expands what a sandboxed process can access.
///
/// `/proc`, `/sys`, and blanket `/dev` are deliberately excluded:
/// - `/proc` — exposes host process info, environ, ASLR layout
/// - `/sys` — Landlock is hierarchical, so `/sys` transitively
///   grants `/sys/fs/cgroup/**` read (cgroup path invariant)
/// - `/dev` (blanket) — exposes `/dev/shm`, `/dev/kmsg`
/// - `/dev/fd`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr` — symlinks
///   to `/proc/self/fd/*`, re-opening the `/proc` exposure after
///   `canonicalize_paths()` resolves them
/// - `/dev/pts` — hierarchical access to all host pseudo-terminals
/// - `/dev/tty` — canonicalizes to the parent's `/dev/pts/N`,
///   granting Landlock read access to the parent's terminal device
///
/// Paths are NOT canonicalized here — the caller handles that after
/// merging with user-specified `-v` paths.
#[cfg(target_os = "linux")]
pub fn default_sandbox_paths() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let read = vec![
        // System binaries and libraries.
        PathBuf::from("/usr"),
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/bin"),
        PathBuf::from("/sbin"),
        // TLS certificates.
        PathBuf::from("/etc/ssl"),
        PathBuf::from("/etc/pki"),
        PathBuf::from("/etc/ca-certificates"),
        // Name resolution and dynamic linking.
        PathBuf::from("/etc/resolv.conf"),
        PathBuf::from("/etc/hosts"),
        PathBuf::from("/etc/host.conf"),
        PathBuf::from("/etc/nsswitch.conf"),
        PathBuf::from("/etc/ld.so.cache"),
        // Locale and user info.
        PathBuf::from("/etc/localtime"),
        PathBuf::from("/etc/passwd"),
        PathBuf::from("/etc/group"),
        // Device nodes (curated, not blanket /dev).
        PathBuf::from("/dev/null"),
        PathBuf::from("/dev/zero"),
        PathBuf::from("/dev/urandom"),
        PathBuf::from("/dev/random"),
        // NOTE: /tmp is intentionally NOT granted by default — it is
        // host-shared and would leak any secret placed there by other
        // processes/users. Callers must opt in explicitly via
        // `-v /tmp/some-subdir` (or similar) if they need it visible.
    ];
    let write = Vec::new();
    (read, write)
}

/// macOS: Seatbelt profile handles system paths.
#[cfg(target_os = "macos")]
pub fn default_sandbox_paths() -> (Vec<PathBuf>, Vec<PathBuf>) {
    (Vec::new(), Vec::new())
}

/// Windows: AppContainer handles system DLL access.
#[cfg(target_os = "windows")]
pub fn default_sandbox_paths() -> (Vec<PathBuf>, Vec<PathBuf>) {
    (Vec::new(), Vec::new())
}

/// Fallback for unsupported platforms.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn default_sandbox_paths() -> (Vec<PathBuf>, Vec<PathBuf>) {
    (Vec::new(), Vec::new())
}

/// Create a temporary directory with a random suffix.
///
/// Uses the `tempfile` crate which calls `mkdtemp` on Unix (mode 0700,
/// created atomically) and secure temp-dir creation on Windows.
/// `keep()` prevents auto-deletion — the caller owns cleanup.
/// Build the `ARAPUCA_CONNECT_PROXY` env var for the wrapper binary.
///
/// Returns `Some((key, value))` when `allowed_hosts` is non-empty.
/// The value is a comma-separated list of `host:port` pairs.
/// Returns `None` when there are no allowed hosts to configure.
///
/// # Errors
///
/// Returns an error if any host string contains a comma or colon
/// (which would break parsing).
#[cfg(target_os = "linux")]
pub fn connect_proxy_env(
    allowed_hosts: &[crate::bridge::AllowedHost],
) -> crate::Result<Option<(String, String)>> {
    if allowed_hosts.is_empty() {
        return Ok(None);
    }
    let mut parts = Vec::with_capacity(allowed_hosts.len());
    for h in allowed_hosts {
        if h.host.contains(',') || h.host.contains(':') {
            return Err(crate::Error::Validation(format!(
                "allowed host must not contain ',' or ':': {}",
                h.host
            )));
        }
        parts.push(format!("{}:{}", h.host, h.port));
    }
    Ok(Some(("ARAPUCA_CONNECT_PROXY".into(), parts.join(","))))
}

/// Parse the `ARAPUCA_CONNECT_PROXY` environment variable.
///
/// Returns the list of allowed host:port pairs encoded by
/// [`connect_proxy_env`], or `None` if the variable is not set.
#[cfg(target_os = "linux")]
pub fn parse_connect_proxy_env() -> crate::Result<Option<Vec<crate::bridge::AllowedHost>>> {
    let val = match std::env::var("ARAPUCA_CONNECT_PROXY") {
        Ok(v) => v,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(crate::Error::Validation(
                "ARAPUCA_CONNECT_PROXY is not valid UTF-8".into(),
            ));
        }
    };
    let mut hosts = Vec::new();
    for pair in val.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some(colon) = pair.rfind(':') else {
            return Err(crate::Error::Validation(format!(
                "invalid ARAPUCA_CONNECT_PROXY entry (expected host:port): {pair}"
            )));
        };
        let host = pair[..colon].to_string();
        let port_str = &pair[colon + 1..];
        let port = port_str.parse::<u16>().map_err(|_| {
            crate::Error::Validation(format!(
                "invalid port in ARAPUCA_CONNECT_PROXY entry: {pair}"
            ))
        })?;
        if port == 0 {
            return Err(crate::Error::Validation(format!(
                "port must be 1-65535 in ARAPUCA_CONNECT_PROXY entry: {pair}"
            )));
        }
        hosts.push(crate::bridge::AllowedHost::new(host, port));
    }
    if hosts.is_empty() {
        return Ok(None);
    }
    Ok(Some(hosts))
}

fn make_temp_dir(prefix: &str) -> crate::Result<PathBuf> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(std::env::temp_dir())?;
    Ok(dir.keep())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_env_contains_essentials() {
        let env = minimal_env(Path::new("/tmp/test"));
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"HOME"));
        assert!(keys.contains(&"TMPDIR"));
        assert!(keys.contains(&"PATH"));
        assert!(keys.contains(&"LANG"));
        assert_eq!(env.len(), 4);
    }

    #[test]
    fn parse_paths_empty() {
        assert!(parse_paths("").is_empty());
    }

    #[test]
    fn parse_paths_single() {
        let paths = parse_paths("/usr/lib");
        assert_eq!(paths, vec![PathBuf::from("/usr/lib")]);
    }

    #[test]
    fn parse_paths_multiple() {
        let sep = PATH_LIST_SEP;
        let input = format!("/a{sep}/b{sep}/c");
        let paths = parse_paths(&input);
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/a"),
                PathBuf::from("/b"),
                PathBuf::from("/c")
            ]
        );
    }

    #[test]
    fn parse_paths_trims_whitespace() {
        let sep = PATH_LIST_SEP;
        let input = format!(" /a {sep} /b ");
        let paths = parse_paths(&input);
        assert_eq!(paths, vec![PathBuf::from("/a"), PathBuf::from("/b")]);
    }

    #[test]
    fn filter_drops_arapuca_prefix() {
        let env = vec![("ARAPUCA_READ_PATHS".into(), "/".into())];
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert_eq!(result.dropped.len(), 1);
        assert_eq!(result.dropped[0].reason, DropReason::ArapucaPrefix);
    }

    #[test]
    fn filter_drops_ld_prefix() {
        let env = vec![
            ("LD_PRELOAD".into(), "/evil.so".into()),
            ("LD_LIBRARY_PATH".into(), "/tmp".into()),
        ];
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert_eq!(result.dropped.len(), 2);
        assert!(
            result
                .dropped
                .iter()
                .all(|d| d.reason == DropReason::LdPrefix)
        );
    }

    #[test]
    fn filter_drops_dyld_prefix() {
        let env = vec![("DYLD_INSERT_LIBRARIES".into(), "/evil.dylib".into())];
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert_eq!(result.dropped[0].reason, DropReason::DyldPrefix);
    }

    /// Contract test: every proxy var forwarded by `--allow-proxy-env`
    /// (see the darwin launcher) must be dropped by `filter_caller_env`,
    /// so re-injecting from the trusted launcher env is safe and the two
    /// lists cannot silently drift apart.
    #[test]
    fn filter_drops_all_proxy_vars_that_allow_proxy_env_forwards() {
        let forwarded = [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        ];
        for key in &forwarded {
            let env = vec![((*key).to_string(), "http://proxy".into())];
            let result = filter_caller_env(&env);
            assert!(
                result.passed.is_empty(),
                "filter must drop {key} so allow_proxy_env can safely re-inject it"
            );
            assert_eq!(result.dropped[0].reason, DropReason::RuntimeInjection);
        }
    }

    #[test]
    fn filter_drops_interpreter_injection() {
        let blocked = vec![
            "BASH_ENV",
            "ENV",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "NODE_OPTIONS",
            "PERL5OPT",
            "PERL5LIB",
        ];
        let env: Vec<(String, String)> = blocked
            .iter()
            .map(|k| (k.to_string(), "malicious".into()))
            .collect();
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert!(
            result
                .dropped
                .iter()
                .all(|d| d.reason == DropReason::InterpreterInjection)
        );
    }

    #[test]
    fn filter_drops_agent_network_proxy() {
        let env = vec![("AGENT_NETWORK_PROXY".into(), "/tmp/evil.sock".into())];
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert_eq!(result.dropped[0].reason, DropReason::LauncherReserved);
    }

    #[test]
    fn filter_preserves_normal_vars() {
        let env = vec![
            ("MY_TOKEN".into(), "secret123".into()),
            ("JIRA_URL".into(), "https://jira.example.com".into()),
        ];
        let result = filter_caller_env(&env);
        assert_eq!(result.passed.len(), 2);
        assert_eq!(result.passed[0].0, "MY_TOKEN");
        assert_eq!(result.passed[1].0, "JIRA_URL");
        assert!(result.dropped.is_empty());
    }

    #[test]
    fn filter_preserves_value_with_equals() {
        let env = vec![("CONFIG".into(), "key=value=extra".into())];
        let result = filter_caller_env(&env);
        assert_eq!(result.passed.len(), 1);
        assert_eq!(result.passed[0].1, "key=value=extra");
    }

    #[test]
    fn filter_drops_dotnet_prefix() {
        let env = vec![
            ("DOTNET_EnableDiagnostics".into(), "1".into()),
            ("CORECLR_PROFILER".into(), "evil".into()),
            ("COR_ENABLE_PROFILING".into(), "1".into()),
            ("COMPLUS_ForceENC".into(), "1".into()),
        ];
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert!(
            result
                .dropped
                .iter()
                .all(|d| d.reason == DropReason::DotnetPrefix)
        );
    }

    #[test]
    fn filter_drops_shell_injection() {
        let env = vec![
            ("COMSPEC".into(), "cmd.exe".into()),
            ("PATHEXT".into(), ".exe".into()),
        ];
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert!(
            result
                .dropped
                .iter()
                .all(|d| d.reason == DropReason::ShellInjection)
        );
    }

    #[test]
    fn filter_drops_compat_layer() {
        let env = vec![("__COMPAT_LAYER".into(), "RunAsInvoker".into())];
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert_eq!(result.dropped[0].reason, DropReason::WindowsShimInjection);
    }

    #[test]
    fn filter_mixed_pass_and_drop() {
        let env = vec![
            ("SAFE_VAR".into(), "ok".into()),
            ("LD_PRELOAD".into(), "/evil.so".into()),
            ("ANOTHER_SAFE".into(), "ok".into()),
        ];
        let result = filter_caller_env(&env);
        assert_eq!(result.passed.len(), 2);
        assert_eq!(result.dropped.len(), 1);
        assert_eq!(result.dropped[0].key, "LD_PRELOAD");
    }

    #[test]
    fn canonicalize_existing_paths() {
        let existing = std::env::temp_dir();
        let nonexistent_child = existing.join("nonexistent-xyz-arapuca-test");
        let paths = vec![existing.clone(), nonexistent_child];
        let result = canonicalize_paths(&paths);
        let canon_existing = std::fs::canonicalize(&existing).unwrap();
        assert!(result.contains(&canon_existing));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn canonicalize_fully_nonexistent() {
        let paths = vec![PathBuf::from("/no-such-parent-xyz/child")];
        let result = canonicalize_paths(&paths);
        assert!(result.is_empty());
    }

    #[test]
    fn bridge_env_both_set() {
        let result = bridge_env(true, Some(Path::new("/tmp/proxy.sock"))).unwrap();
        let (key, value) = result.unwrap();
        assert_eq!(key, "ARAPUCA_PROXY_BRIDGE");
        assert_eq!(value, format!("{BRIDGE_PORT}:/tmp/proxy.sock"));
    }

    #[test]
    fn bridge_env_no_netns() {
        let result = bridge_env(false, Some(Path::new("/tmp/proxy.sock"))).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn bridge_env_no_socket() {
        let result = bridge_env(true, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn bridge_env_neither_set() {
        let result = bridge_env(false, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn bridge_env_colon_in_path() {
        let result = bridge_env(true, Some(Path::new("/tmp/bad:path.sock")));
        assert!(result.is_err());
    }

    #[test]
    fn wrapper_env_omits_per_uid_rlimits() {
        let profile = crate::Profile {
            max_memory_mb: 256,
            max_pids: 100,
            max_file_size_mb: 512,
            ..Default::default()
        };
        let env = wrapper_env(&profile).unwrap();
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            !keys.contains(&"ARAPUCA_RLIMIT_AS"),
            "wrapper_env must not emit ARAPUCA_RLIMIT_AS"
        );
        assert!(
            !keys.contains(&"ARAPUCA_RLIMIT_NPROC"),
            "wrapper_env must not emit ARAPUCA_RLIMIT_NPROC"
        );
    }

    #[test]
    fn wrapper_env_emits_remaining_rlimits() {
        let profile = crate::Profile {
            max_memory_mb: 256,
            max_pids: 100,
            max_file_size_mb: 512,
            max_open_files: 1024,
            read_paths: vec![PathBuf::from("/usr")],
            ..Default::default()
        };
        let env = wrapper_env(&profile).unwrap();
        let map: std::collections::HashMap<&str, &str> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        let fsize_bytes = (512u64 * 1024 * 1024).to_string();
        assert_eq!(map.get("ARAPUCA_RLIMIT_FSIZE"), Some(&fsize_bytes.as_str()));
        assert_eq!(map.get("ARAPUCA_RLIMIT_NOFILE"), Some(&"1024"));
        assert_eq!(map.get("ARAPUCA_READ_PATHS"), Some(&"/usr"));
        assert!(!map.contains_key("ARAPUCA_RLIMIT_NPROC"));
    }

    #[cfg(unix)]
    #[test]
    fn tmpdir_guard_cleans_up_on_drop() {
        let dir = make_tmp_dir("guard-drop-test").unwrap();
        assert!(dir.exists());
        {
            let _guard = TmpDirGuard::new(dir.clone());
        }
        assert!(!dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn tmpdir_guard_defuse_preserves_dir() {
        let dir = make_tmp_dir("guard-defuse-test").unwrap();
        assert!(dir.exists());
        let path = {
            let guard = TmpDirGuard::new(dir.clone());
            guard.defuse()
        };
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn filter_drops_shell_injection_extended() {
        let env: Vec<(String, String)> = ["ZDOTDIR", "IFS", "PROMPT_COMMAND"]
            .iter()
            .map(|k| (k.to_string(), "x".into()))
            .collect();
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert_eq!(result.dropped.len(), 3);
        assert!(
            result
                .dropped
                .iter()
                .all(|d| d.reason == DropReason::InterpreterInjection)
        );
    }

    #[test]
    fn filter_drops_openssl_conf() {
        let env = vec![("OPENSSL_CONF".into(), "/evil.cnf".into())];
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert_eq!(result.dropped[0].reason, DropReason::RuntimeInjection);
    }

    #[test]
    fn filter_drops_editor_vars() {
        let env: Vec<(String, String)> = ["EDITOR", "VISUAL", "PAGER"]
            .iter()
            .map(|k| (k.to_string(), "/bin/sh".into()))
            .collect();
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert!(
            result
                .dropped
                .iter()
                .all(|d| d.reason == DropReason::RuntimeInjection)
        );
    }

    #[test]
    fn filter_drops_git_injection() {
        let env: Vec<(String, String)> = [
            "GIT_EXEC_PATH",
            "GIT_TEMPLATE_DIR",
            "GIT_EXTERNAL_DIFF",
            "GIT_ASKPASS",
            "GIT_SSH",
        ]
        .iter()
        .map(|k| (k.to_string(), "/evil".into()))
        .collect();
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert!(
            result
                .dropped
                .iter()
                .all(|d| d.reason == DropReason::RuntimeInjection)
        );
    }

    #[test]
    fn filter_drops_proxy_extended() {
        let env: Vec<(String, String)> = ["ftp_proxy", "SOCKS_PROXY", "CGI_HTTP_PROXY"]
            .iter()
            .map(|k| (k.to_string(), "http://evil".into()))
            .collect();
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert!(
            result
                .dropped
                .iter()
                .all(|d| d.reason == DropReason::RuntimeInjection)
        );
    }

    #[test]
    fn filter_drops_cargo_home() {
        let env = vec![("CARGO_HOME".into(), "/tmp/evil-cargo".into())];
        let result = filter_caller_env(&env);
        assert!(result.passed.is_empty());
        assert_eq!(result.dropped[0].reason, DropReason::RuntimeInjection);
    }

    #[test]
    fn default_sandbox_paths_no_default_writes() {
        let (_read, write) = default_sandbox_paths();
        assert!(
            write.is_empty(),
            "default write paths should be empty (private temp dir is added by the launcher)"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_sandbox_paths_linux_includes_system() {
        let (read, write) = default_sandbox_paths();
        assert!(read.iter().any(|p| p == Path::new("/usr")));
        assert!(read.iter().any(|p| p == Path::new("/bin")));
        assert!(read.iter().any(|p| p == Path::new("/dev/null")));
        assert!(write.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_sandbox_paths_linux_excludes_tmp() {
        // /tmp is host-shared; it must not be granted by default or a
        // sandboxed process can read secrets left there by others.
        let (read, _write) = default_sandbox_paths();
        assert!(!read.iter().any(|p| p == Path::new("/tmp")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_sandbox_paths_linux_excludes_virtual_fs() {
        let (read, write) = default_sandbox_paths();
        let all: Vec<&Path> = read
            .iter()
            .chain(write.iter())
            .map(|p| p.as_path())
            .collect();

        // Blanket /proc, /sys, /dev must not be present.
        assert!(!all.contains(&Path::new("/proc")), "must not include /proc");
        assert!(!all.contains(&Path::new("/sys")), "must not include /sys");
        assert!(
            !all.contains(&Path::new("/dev")),
            "must not include blanket /dev"
        );

        // Symlinks into /proc must not be present.
        assert!(
            !all.contains(&Path::new("/dev/fd")),
            "must not include /dev/fd (symlink to /proc/self/fd)"
        );
        assert!(
            !all.contains(&Path::new("/dev/stdin")),
            "must not include /dev/stdin"
        );
        assert!(
            !all.contains(&Path::new("/dev/stdout")),
            "must not include /dev/stdout"
        );
        assert!(
            !all.contains(&Path::new("/dev/stderr")),
            "must not include /dev/stderr"
        );

        // /dev/pts grants hierarchical access to all host PTYs.
        assert!(
            !all.contains(&Path::new("/dev/pts")),
            "must not include /dev/pts"
        );

        // /dev/tty canonicalizes to parent's /dev/pts/N.
        assert!(
            !all.contains(&Path::new("/dev/tty")),
            "must not include /dev/tty"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_sandbox_paths_linux_no_cgroup_ancestor() {
        let (read, write) = default_sandbox_paths();
        let cgroup = Path::new("/sys/fs/cgroup");
        for p in read.iter().chain(write.iter()) {
            assert!(
                !cgroup.starts_with(p),
                "path {} is an ancestor of /sys/fs/cgroup",
                p.display()
            );
        }
    }
}
