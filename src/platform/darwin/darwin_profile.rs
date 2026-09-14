//! Seatbelt profile generation for macOS sandbox-exec.
//!
//! Generates `.sb` profile files in Apple's Seatbelt policy language.
//! The profile starts with `(deny default)` and explicitly allows only
//! the paths and operations the sandboxed process needs.
//!
//! Path validation prevents Seatbelt profile injection attacks — only a
//! strict character allowlist is accepted.

use std::fmt::Write;
use std::path::Path;

use crate::Error;

/// Data used to render a Seatbelt profile.
pub struct ProfileData {
    /// Paths the subprocess can read.
    pub read_paths: Vec<String>,
    /// Paths the subprocess can read and write.
    pub write_paths: Vec<String>,
    /// Paths the subprocess can execute (in addition to system defaults).
    pub exec_paths: Vec<String>,
    /// Path to the JSON-RPC control socket.
    pub control_socket: Option<String>,
    /// Path to the LLM proxy socket.
    pub llm_socket: Option<String>,
    /// Allow outbound network access (TCP + DNS via mDNSResponder).
    ///
    /// Maps from `SeccompProfile::Baseline` on the caller side. When
    /// true, the profile grants unrestricted TCP outbound and the Mach
    /// IPC services needed for DNS and TLS on macOS. There is no
    /// per-host filtering (unlike Linux's netns + CONNECT proxy).
    pub allow_network: bool,
    /// Allow access to the macOS Keychain.
    ///
    /// When true, the profile grants the `securityd`/`trustd` Mach
    /// lookups and read access to the Keychain database files so
    /// `Security.framework` can read Keychain items (e.g. an app's
    /// stored OAuth token). Without this, a deny-default profile makes
    /// Keychain reads fail silently and Keychain-backed authentication
    /// reports "not logged in".
    pub allow_keychain: bool,
    /// Allow ioctl on PTY slave devices.
    ///
    /// When true, the profile grants `file-ioctl` scoped to `/dev/ttys*`
    /// so the sandboxed process can call `tcsetattr`/`tcgetattr` (e.g.
    /// `setRawMode` in Node.js). Only needed when the process has a PTY
    /// slave as its controlling terminal.
    pub tty: bool,
}

/// Validate that a path contains only safe characters for embedding in
/// a Seatbelt profile.
///
/// This prevents injection attacks where a crafted path could break out
/// of the `(subpath ...)` or `(literal ...)` expressions in the profile.
///
/// Allowed characters: `[a-zA-Z0-9/_. @-]`
pub fn validate_profile_path(path: &str) -> crate::Result<()> {
    if path.is_empty() {
        return Err(Error::Validation("empty path".into()));
    }
    if !path.starts_with('/') {
        return Err(Error::Validation(format!("path must be absolute: {path}")));
    }
    if path.split('/').any(|c| c == "..") {
        return Err(Error::Validation(format!("path contains '..': {path}")));
    }
    for ch in path.chars() {
        if !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '/' | '_' | '.' | ' ' | '-' | '@' | '+')
        {
            return Err(Error::Validation(format!(
                "invalid character in sandbox profile path: {:?}",
                ch
            )));
        }
    }
    Ok(())
}

/// Collect the ancestor directories of every user mount path.
///
/// Seatbelt resolves `realpath()` / `chdir()` (and Rust's
/// `std::fs::canonicalize`) by walking the path from `/` downward, calling
/// `lstat` on each component. Each `lstat` requires `file-read-metadata` on
/// that component. Granting only `(subpath "<mount>")` covers the mount and
/// its children but NOT its parents, so canonicalizing a mount nested below
/// a non-system directory (e.g. `/Users/<user>/.c3/worktrees/<run>`) fails
/// with EPERM at the first un-granted ancestor (`/Users/<user>`).
///
/// Returns each intermediate directory from just below root down to the
/// parent of each mount (the mount itself is already covered by its
/// `subpath` rule). Deduplicated and sorted for a deterministic profile.
///
/// Callers pass read/write paths only, not exec paths. Exec binaries are
/// covered by the system `subpath` grants (`/usr`, `/bin`, `/opt/homebrew`),
/// by exec paths that are also read paths, and by the hardcoded `/Users` and
/// `/opt` ancestors.
fn mount_ancestors(paths: &[String]) -> Vec<String> {
    let mut set = std::collections::BTreeSet::new();
    for p in paths {
        // Build cumulative prefixes: "/a", "/a/b", ... excluding the full
        // path itself (covered by its own subpath grant).
        let mut prefix = String::new();
        let comps: Vec<&str> = p.split('/').filter(|c| !c.is_empty()).collect();
        for comp in comps.iter().take(comps.len().saturating_sub(1)) {
            prefix.push('/');
            prefix.push_str(comp);
            set.insert(prefix.clone());
        }
    }
    set.into_iter().collect()
}

/// Generate a Seatbelt `.sb` profile and write it to `dir/profile.sb`.
///
/// Returns the path to the generated profile file.
pub fn generate_profile(dir: &Path, data: &ProfileData) -> crate::Result<std::path::PathBuf> {
    // Validate all paths before generating the profile.
    for p in &data.read_paths {
        validate_profile_path(p)?;
    }
    for p in &data.write_paths {
        validate_profile_path(p)?;
    }
    for p in &data.exec_paths {
        validate_profile_path(p)?;
    }
    if let Some(ref s) = data.control_socket {
        validate_profile_path(s)?;
    }
    if let Some(ref s) = data.llm_socket {
        validate_profile_path(s)?;
    }

    let mut profile = String::with_capacity(4096);

    // Header: deny everything by default.
    writeln!(profile, "(version 1)").unwrap();
    writeln!(profile, "(deny default)").unwrap();
    writeln!(profile).unwrap();

    // Process operations.
    writeln!(profile, "; Process").unwrap();
    writeln!(profile, "(allow process-fork)").unwrap();
    writeln!(profile, "(allow signal (target self))").unwrap();
    writeln!(profile).unwrap();

    // Root directory: dyld needs file-read* access to stat "/" during
    // process bootstrap. Seatbelt requires the data grant here; narrowing it
    // to metadata causes dyld to abort before main() runs.
    // Without this, the process receives SIGABRT before main() runs.
    writeln!(profile, "; Root directory (dyld bootstrap)").unwrap();
    writeln!(profile, "(allow file-read* (literal \"/\"))").unwrap();
    writeln!(profile).unwrap();

    // Ancestor directories for path traversal. Seatbelt requires
    // explicit access to parent directories for realpath() resolution.
    // /private and /private/var are needed because /var, /etc, and /tmp
    // are symlinks into /private on macOS.
    // /etc, /tmp, and /var are symlinks into /private — their entries
    // must be resolvable so processes that use non-canonical paths
    // (e.g. /tmp/<x>, /var/select/developer_dir) can traverse the link.
    writeln!(profile, "; Ancestor directories for path traversal").unwrap();
    for ancestor in &[
        "/opt",
        "/etc",
        "/tmp",
        "/var",
        "/Users",
        "/private",
        "/private/var",
    ] {
        writeln!(
            profile,
            "(allow file-read-metadata (literal \"{ancestor}\"))"
        )
        .unwrap();
    }
    writeln!(profile).unwrap();

    // System read paths (always allowed).
    // Note: /System covers /System/Library and /System/Cryptexes (dyld
    // shared cache on macOS 13+).
    writeln!(profile, "; System read paths").unwrap();
    for sys_path in &[
        "/usr",
        "/bin",
        "/opt/homebrew",
        "/Library/Frameworks",
        "/System",
        "/private/var/select",
        "/private/var/db/timezone",
    ] {
        writeln!(profile, "(allow file-read* (subpath \"{sys_path}\"))").unwrap();
    }
    // Specific device nodes — not blanket /dev which would expose
    // disk devices, DTrace, and pseudo-terminals.
    for dev in &["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"] {
        writeln!(profile, "(allow file-read* (literal \"{dev}\"))").unwrap();
    }
    writeln!(profile, "(allow file-read* (subpath \"/dev/fd\"))").unwrap();
    if data.tty {
        writeln!(profile, "(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))").unwrap();
    }
    writeln!(profile).unwrap();

    // Specific /etc files (not the whole directory).
    // macOS paths: /etc -> /private/etc, so use canonical paths.
    // Seatbelt resolves symlinks in access paths but stores profile
    // paths as-is, so /etc/hosts would NOT match an access to
    // /private/etc/hosts.
    writeln!(profile, "; Specific /etc files (canonical paths)").unwrap();
    for etc_file in &[
        "/private/etc/hosts",
        "/private/etc/resolv.conf",
        "/private/etc/localtime",
    ] {
        writeln!(profile, "(allow file-read* (literal \"{etc_file}\"))").unwrap();
    }
    // Allow reading /etc/ssl for certificates and OpenSSL configuration.
    writeln!(profile, "(allow file-read* (subpath \"/private/etc/ssl\"))").unwrap();
    writeln!(profile).unwrap();

    // User read paths.
    if !data.read_paths.is_empty() {
        writeln!(profile, "; User read paths").unwrap();
        for p in &data.read_paths {
            writeln!(profile, "(allow file-read* (subpath \"{p}\"))").unwrap();
        }
        writeln!(profile).unwrap();
    }

    // User write paths.
    if !data.write_paths.is_empty() {
        writeln!(profile, "; User write paths").unwrap();
        for p in &data.write_paths {
            writeln!(profile, "(allow file-read* (subpath \"{p}\"))").unwrap();
            writeln!(profile, "(allow file-write* (subpath \"{p}\"))").unwrap();
        }
        writeln!(profile).unwrap();
    }

    // Ancestor traversal for user mounts. A mount's `subpath` grant does not
    // cover its parent directories; without metadata access to each ancestor,
    // realpath()/chdir()/canonicalize on a deeply-nested mount fails with
    // EPERM at the first un-granted parent. Grant metadata-only (not read*)
    // so directory contents stay deny-by-default — only traversal is opened.
    {
        let mut user_paths = data.read_paths.clone();
        user_paths.extend(data.write_paths.iter().cloned());
        let ancestors = mount_ancestors(&user_paths);
        if !ancestors.is_empty() {
            writeln!(profile, "; Ancestor traversal for user mounts").unwrap();
            for a in &ancestors {
                writeln!(profile, "(allow file-read-metadata (literal \"{a}\"))").unwrap();
            }
            writeln!(profile).unwrap();
        }
    }

    // /dev/null write access.
    writeln!(profile, "; /dev/null write").unwrap();
    writeln!(profile, "(allow file-write* (literal \"/dev/null\"))").unwrap();
    writeln!(profile).unwrap();

    // Exec permissions: system paths + user exec paths + write paths
    // (uv creates virtualenvs in write paths that need to be executable).
    writeln!(profile, "; Exec").unwrap();
    writeln!(profile, "(allow process-exec (subpath \"/usr\"))").unwrap();
    writeln!(profile, "(allow process-exec (subpath \"/bin\"))").unwrap();
    writeln!(profile, "(allow process-exec (subpath \"/opt/homebrew\"))").unwrap();
    for p in &data.exec_paths {
        writeln!(profile, "(allow process-exec (subpath \"{p}\"))").unwrap();
    }
    // Write paths are also exec paths (virtualenvs).
    for p in &data.write_paths {
        writeln!(profile, "(allow process-exec (subpath \"{p}\"))").unwrap();
    }
    writeln!(profile).unwrap();

    // Network: baseline mode allows TCP outbound and DNS via
    // mDNSResponder. Strict mode (default) blocks all network via
    // (deny default).
    if data.allow_network {
        writeln!(profile, "; Network (baseline mode)").unwrap();
        for meta_path in &[
            "/private",
            "/private/var",
            "/private/etc",
            "/usr",
            "/System",
            "/Library",
            "/var",
            "/etc",
            "/tmp",
        ] {
            writeln!(
                profile,
                "(allow file-read-metadata (subpath \"{meta_path}\"))"
            )
            .unwrap();
        }
        writeln!(profile, "(allow network-outbound (remote tcp))").unwrap();
        // mDNSResponder — DNS resolution on macOS goes through this socket.
        writeln!(
            profile,
            "(allow network-outbound (remote unix-socket (path-literal \"/private/var/run/mDNSResponder\")))"
        )
        .unwrap();
        writeln!(profile, "(allow network-outbound").unwrap();
        writeln!(profile, "  (control-name \"com.apple.netsrc\")").unwrap();
        writeln!(
            profile,
            "  (control-name \"com.apple.network.statistics\"))"
        )
        .unwrap();
        writeln!(profile, "(allow system-socket").unwrap();
        writeln!(
            profile,
            "  (require-all (socket-domain AF_SYSTEM) (socket-protocol 2))"
        )
        .unwrap();
        writeln!(profile, "  (socket-domain AF_ROUTE))").unwrap();
        writeln!(profile).unwrap();

        // File reads for network stack (from Apple's system-network).
        writeln!(profile, "; Network stack files").unwrap();
        writeln!(
            profile,
            "(allow file-read* (literal \"/Library/Preferences/com.apple.networkd.plist\"))"
        )
        .unwrap();
        writeln!(
            profile,
            "(allow file-read* (literal \"/private/var/db/nsurlstoraged/dafsaData.bin\"))"
        )
        .unwrap();
        writeln!(profile).unwrap();
    } else if data.control_socket.is_some() || data.llm_socket.is_some() {
        writeln!(
            profile,
            "; Unix sockets (strict mode — scoped to configured paths)"
        )
        .unwrap();
        if let Some(ref s) = data.control_socket {
            writeln!(
                profile,
                "(allow network-outbound (remote unix-socket (path-literal \"{s}\")))"
            )
            .unwrap();
            writeln!(profile, "(allow file-read* (literal \"{s}\"))").unwrap();
            writeln!(profile, "(allow file-write* (literal \"{s}\"))").unwrap();
        }
        if let Some(ref s) = data.llm_socket {
            writeln!(
                profile,
                "(allow network-outbound (remote unix-socket (path-literal \"{s}\")))"
            )
            .unwrap();
            writeln!(profile, "(allow file-read* (literal \"{s}\"))").unwrap();
            writeln!(profile, "(allow file-write* (literal \"{s}\"))").unwrap();
        }
        writeln!(profile).unwrap();
    }

    // Socket permissions in network mode (scoped to configured paths).
    if data.allow_network && (data.control_socket.is_some() || data.llm_socket.is_some()) {
        if let Some(ref s) = data.control_socket {
            writeln!(
                profile,
                "(allow network-outbound (remote unix-socket (path-literal \"{s}\")))"
            )
            .unwrap();
            writeln!(profile, "(allow file-read* (literal \"{s}\"))").unwrap();
            writeln!(profile, "(allow file-write* (literal \"{s}\"))").unwrap();
        }
        if let Some(ref s) = data.llm_socket {
            writeln!(
                profile,
                "(allow network-outbound (remote unix-socket (path-literal \"{s}\")))"
            )
            .unwrap();
            writeln!(profile, "(allow file-read* (literal \"{s}\"))").unwrap();
            writeln!(profile, "(allow file-write* (literal \"{s}\"))").unwrap();
        }
        writeln!(profile).unwrap();
    }

    // Mach IPC (required for basic macOS operation).
    writeln!(profile, "; Mach IPC").unwrap();
    writeln!(
        profile,
        "(allow mach-lookup (global-name \"com.apple.system.logger\"))"
    )
    .unwrap();
    writeln!(
        profile,
        "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))"
    )
    .unwrap();
    writeln!(
        profile,
        "(allow mach-lookup (global-name \"com.apple.system.notification_center\"))"
    )
    .unwrap();

    if data.allow_network {
        // Apple system-network Mach services (from system.sb).
        writeln!(
            profile,
            "(allow mach-lookup (global-name \"com.apple.dnssd.service\"))"
        )
        .unwrap();
        writeln!(
            profile,
            "(allow mach-lookup (global-name \"com.apple.nehelper\"))"
        )
        .unwrap();
        writeln!(
            profile,
            "(allow mach-lookup (global-name \"com.apple.nesessionmanager\"))"
        )
        .unwrap();
        writeln!(
            profile,
            "(allow mach-lookup (global-name \"com.apple.networkd\"))"
        )
        .unwrap();
        writeln!(
            profile,
            "(allow mach-lookup (global-name \"com.apple.symptomsd\"))"
        )
        .unwrap();
        writeln!(
            profile,
            "(allow mach-lookup (global-name \"com.apple.usymptomsd\"))"
        )
        .unwrap();
        writeln!(
            profile,
            "(allow mach-lookup (global-name \"com.apple.SystemConfiguration.SCNetworkReachability\"))"
        )
        .unwrap();
        writeln!(
            profile,
            "(allow mach-lookup (global-name \"com.apple.cfnetwork.cfnetworkagent\"))"
        )
        .unwrap();
        // TLS certificate validation.
        writeln!(
            profile,
            "(allow mach-lookup (global-name \"com.apple.trustd\"))"
        )
        .unwrap();
        writeln!(
            profile,
            "(allow mach-lookup (global-name \"com.apple.trustd.agent\"))"
        )
        .unwrap();
        // DNS and network configuration.
        writeln!(
            profile,
            "(allow mach-lookup (global-name \"com.apple.SystemConfiguration.configd\"))"
        )
        .unwrap();
    }
    writeln!(profile).unwrap();

    // Keychain access (opt-in via --allow-keychain).
    //
    // Reading a Keychain item goes through securityd over Mach IPC;
    // trustd/ocspd back certificate trust evaluation. The file-based
    // login keychain is also read directly by Security.framework, so
    // grant read access to the system Keychain directory and the
    // metadata store. The user's login keychain directory
    // (~/Library/Keychains) is added to read_paths by the launcher.
    if data.allow_keychain {
        writeln!(profile, "; Keychain (--allow-keychain)").unwrap();
        let mut services = vec!["com.apple.SecurityServer", "com.apple.ocspd"];
        // trustd/trustd.agent back certificate trust evaluation. When
        // networking is enabled they are already granted in the network
        // block above, so only emit them here to avoid a duplicate.
        if !data.allow_network {
            services.push("com.apple.trustd");
            services.push("com.apple.trustd.agent");
        }
        for service in &services {
            writeln!(profile, "(allow mach-lookup (global-name \"{service}\"))").unwrap();
        }
        for path in &[
            "/Library/Keychains",
            "/System/Library/Keychains",
            "/private/var/db/mds",
        ] {
            writeln!(profile, "(allow file-read* (subpath \"{path}\"))").unwrap();
        }
        writeln!(profile).unwrap();
    }

    // POSIX shared memory (read-only).
    writeln!(profile, "; POSIX shm").unwrap();
    writeln!(profile, "(allow ipc-posix-shm-read-data)").unwrap();
    writeln!(profile).unwrap();

    // Sysctl read.
    writeln!(profile, "; Sysctl").unwrap();
    writeln!(profile, "(allow sysctl-read)").unwrap();

    // Write profile to file.
    let profile_path = dir.join("profile.sb");
    std::fs::write(&profile_path, &profile)?;

    // Set permissions to 0400 (read-only for owner).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&profile_path, std::fs::Permissions::from_mode(0o400))?;
    }

    Ok(profile_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_profile_path_valid() {
        // Simple path.
        assert!(validate_profile_path("/usr/bin/python3").is_ok());
        // Homebrew path.
        assert!(validate_profile_path("/opt/homebrew/bin").is_ok());
        // Path with spaces.
        assert!(validate_profile_path("/Users/test user/dir").is_ok());
        // Underscore and dash.
        assert!(validate_profile_path("/tmp/my_dir-name").is_ok());
        // @ in Homebrew versioned paths.
        assert!(validate_profile_path("/opt/homebrew/opt/python@3.14/bin/python3.14").is_ok());
        // Dots.
        assert!(validate_profile_path("/usr/lib/libfoo.1.2.dylib").is_ok());
        // + in C++ library paths.
        assert!(validate_profile_path("/usr/lib/libc++.1.dylib").is_ok());
        assert!(validate_profile_path("/opt/homebrew/Cellar/llvm/17/lib/c++").is_ok());
    }

    #[test]
    fn test_validate_profile_path_invalid() {
        // Empty.
        assert!(validate_profile_path("").is_err());
        // Path traversal.
        assert!(validate_profile_path("/tmp/../etc/passwd").is_err());
        assert!(validate_profile_path("/nonexistent/../etc").is_err());
        // Double quote (profile injection).
        assert!(validate_profile_path("/tmp/foo\"bar").is_err());
        // Parentheses (Seatbelt syntax).
        assert!(validate_profile_path("/tmp/foo(bar)").is_err());
        // Semicolon.
        assert!(validate_profile_path("/tmp/foo;bar").is_err());
        // Backslash.
        assert!(validate_profile_path("/tmp/foo\\bar").is_err());
        // Newline.
        assert!(validate_profile_path("/tmp/foo\nbar").is_err());
        // Null byte.
        assert!(validate_profile_path("/tmp/foo\0bar").is_err());
        // Backtick.
        assert!(validate_profile_path("/tmp/foo`bar").is_err());
        // Single quote.
        assert!(validate_profile_path("/tmp/foo'bar").is_err());
        // Pipe.
        assert!(validate_profile_path("/tmp/foo|bar").is_err());
        // Ampersand.
        assert!(validate_profile_path("/tmp/foo&bar").is_err());
        // Relative path (must be absolute — mount_ancestors() prepends '/').
        assert!(validate_profile_path("foo/bar/baz").is_err());
        assert!(validate_profile_path("tmp").is_err());
        assert!(validate_profile_path("./foo").is_err());
    }

    #[test]
    fn test_generate_profile() {
        let dir = std::env::temp_dir().join("arapuca-test-profile");
        let _ = std::fs::create_dir_all(&dir);

        let data = ProfileData {
            read_paths: vec!["/home/user/src".into()],
            write_paths: vec!["/tmp/work".into()],
            exec_paths: vec!["/usr/local/bin".into()],
            control_socket: Some("/tmp/sock/control.sock".into()),
            llm_socket: Some("/tmp/sock/llm.sock".into()),
            allow_network: false,
            allow_keychain: false,
            tty: false,
        };

        let path = generate_profile(&dir, &data).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        // Verify deny-default.
        assert!(content.contains("(deny default)"));

        // Root requires a broad grant for dyld bootstrap. See the policy
        // comment above; this is an unavoidable Seatbelt exception.
        assert!(content.contains("(allow file-read* (literal \"/\"))"));

        // Verify ancestor directories for path traversal.
        assert!(content.contains("(allow file-read-metadata (literal \"/opt\"))"));
        assert!(content.contains("(allow file-read-metadata (literal \"/etc\"))"));
        // /tmp and /var are symlinks to /private/tmp and /private/var;
        // their entries must be resolvable so tools that use the
        // non-canonical path (e.g. xcode-select via /var/select) work.
        for ancestor in ["/tmp", "/var", "/private", "/Users", "/private/var"] {
            assert!(content.contains(&format!(
                "(allow file-read-metadata (literal \"{ancestor}\"))"
            )));
            assert!(!content.contains(&format!("(allow file-read* (literal \"{ancestor}\"))")));
        }

        // Verify /private/var/select is readable (shell resolution).
        assert!(content.contains("(allow file-read* (subpath \"/private/var/select\"))"));

        // Verify /etc paths use canonical /private/etc prefix.
        assert!(content.contains("(allow file-read* (literal \"/private/etc/hosts\"))"));
        assert!(content.contains("(allow file-read* (subpath \"/private/etc/ssl\"))"));

        // Verify /System is a subpath (covers /System/Library and
        // /System/Cryptexes).
        assert!(content.contains("(allow file-read* (subpath \"/System\"))"));

        // PTY ioctl must NOT be present when tty is false.
        assert!(
            !content.contains("file-ioctl"),
            "file-ioctl must not be granted without tty mode"
        );

        // Verify read paths.
        assert!(content.contains("(allow file-read* (subpath \"/home/user/src\"))"));

        // Verify write paths include both read and write.
        assert!(content.contains("(allow file-read* (subpath \"/tmp/work\"))"));
        assert!(content.contains("(allow file-write* (subpath \"/tmp/work\"))"));

        // Verify scoped unix socket paths (strict mode).
        assert!(content.contains(
            "(allow network-outbound (remote unix-socket (path-literal \"/tmp/sock/control.sock\")))"
        ));
        assert!(content.contains(
            "(allow network-outbound (remote unix-socket (path-literal \"/tmp/sock/llm.sock\")))"
        ));
        assert!(content.contains("(allow file-read* (literal \"/tmp/sock/control.sock\"))"));
        assert!(content.contains("(allow file-write* (literal \"/tmp/sock/llm.sock\"))"));

        // Verify exec paths — explicit + auto-included from write paths.
        assert!(content.contains("(allow process-exec (subpath \"/usr/local/bin\"))"));
        assert!(content.contains("(allow process-exec (subpath \"/tmp/work\"))"));

        // Verify NO network rules in strict mode.
        assert!(
            !content.contains("network-outbound (remote tcp)"),
            "strict mode must not allow TCP outbound"
        );
        assert!(
            !content.contains("com.apple.dnssd.service"),
            "strict mode must not allow network Mach services"
        );

        // Verify file permissions.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o400);
        }

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_profile_tty() {
        let dir = std::env::temp_dir().join("arapuca-test-profile-tty");
        let _ = std::fs::create_dir_all(&dir);

        let data = ProfileData {
            read_paths: vec!["/home/user/src".into()],
            write_paths: vec![],
            exec_paths: vec![],
            control_socket: None,
            llm_socket: None,
            allow_network: false,
            allow_keychain: false,
            tty: true,
        };

        let path = generate_profile(&dir, &data).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        assert!(content.contains("(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mount_ancestors() {
        // Deeply nested mount: every intermediate dir, excluding the mount
        // itself, in sorted order.
        let anc = mount_ancestors(&["/Users/bob/.c3/worktrees/run1".into()]);
        assert_eq!(
            anc,
            vec![
                "/Users".to_string(),
                "/Users/bob".into(),
                "/Users/bob/.c3".into(),
                "/Users/bob/.c3/worktrees".into(),
            ]
        );
        // Two mounts sharing a prefix are deduplicated.
        let anc2 = mount_ancestors(&["/a/b/c".into(), "/a/b/d".into()]);
        assert_eq!(anc2, vec!["/a".to_string(), "/a/b".into()]);
        // A top-level mount has no ancestors below root.
        assert!(mount_ancestors(&["/tmp".into()]).is_empty());
    }

    #[test]
    fn test_generate_profile_grants_mount_ancestor_traversal() {
        let dir = std::env::temp_dir().join("arapuca-test-ancestors");
        let _ = std::fs::create_dir_all(&dir);

        let data = ProfileData {
            read_paths: vec!["/Users/bob/project".into()],
            write_paths: vec!["/Users/bob/.c3/worktrees/run1".into()],
            exec_paths: vec![],
            control_socket: None,
            llm_socket: None,
            allow_network: false,
            allow_keychain: false,
            tty: false,
        };
        let path = generate_profile(&dir, &data).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        // Intermediate ancestors of the nested worktree get metadata-only
        // traversal grants, so canonicalize/chdir into it resolves.
        assert!(content.contains("(allow file-read-metadata (literal \"/Users/bob\"))"));
        assert!(content.contains("(allow file-read-metadata (literal \"/Users/bob/.c3\"))"));
        assert!(
            content.contains("(allow file-read-metadata (literal \"/Users/bob/.c3/worktrees\"))")
        );
        // The mount itself is covered by its subpath grant, not re-granted as
        // a bare metadata literal here — and contents stay deny-by-default
        // (no file-read* subpath for the un-mounted parents).
        assert!(!content.contains("(allow file-read* (literal \"/Users/bob\"))"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_profile_rejects_injection() {
        let dir = std::env::temp_dir().join("arapuca-test-injection");
        let _ = std::fs::create_dir_all(&dir);

        // Crafted path that tries to inject Seatbelt syntax.
        let data = ProfileData {
            read_paths: vec!["/tmp/evil\") (allow default) (deny nothing \"".into()],
            write_paths: vec![],
            exec_paths: vec![],
            control_socket: None,
            llm_socket: None,
            allow_network: false,
            allow_keychain: false,
            tty: false,
        };

        let result = generate_profile(&dir, &data);
        assert!(result.is_err(), "injection path should be rejected");

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_profile_with_network() {
        let dir = std::env::temp_dir().join("arapuca-test-profile-net");
        let _ = std::fs::create_dir_all(&dir);

        let data = ProfileData {
            read_paths: vec!["/home/user/src".into()],
            write_paths: vec!["/tmp/work".into()],
            exec_paths: vec![],
            control_socket: None,
            llm_socket: None,
            allow_network: true,
            allow_keychain: false,
            tty: false,
        };

        let path = generate_profile(&dir, &data).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        // File metadata scoped to system paths (not global).
        assert!(content.contains("(allow file-read-metadata (subpath \"/private/var\"))"));
        assert!(content.contains("(allow file-read-metadata (subpath \"/usr\"))"));
        assert!(
            !content.contains("file-read-metadata (subpath \"/\")"),
            "file-read-metadata must not scope to root"
        );

        // TCP outbound.
        assert!(content.contains("(allow network-outbound (remote tcp))"));

        // mDNSResponder — scoped, not blanket unix.
        assert!(content.contains("mDNSResponder"));
        assert!(
            !content.contains("(allow network-outbound (remote unix))"),
            "unix socket outbound must be scoped, not blanket"
        );

        // Kernel control sockets.
        assert!(content.contains("com.apple.netsrc"));
        assert!(content.contains("com.apple.network.statistics"));

        // System sockets.
        assert!(content.contains("AF_SYSTEM"));
        assert!(content.contains("AF_ROUTE"));

        // Apple system-network Mach services.
        assert!(content.contains("com.apple.dnssd.service"));
        assert!(content.contains("com.apple.networkd"));
        assert!(content.contains("com.apple.SystemConfiguration.SCNetworkReachability"));
        assert!(content.contains("com.apple.cfnetwork.cfnetworkagent"));

        // TLS Mach services.
        assert!(content.contains("com.apple.trustd"));
        assert!(content.contains("com.apple.trustd.agent"));

        // DNS/network configuration.
        assert!(content.contains("com.apple.SystemConfiguration.configd"));

        // Network stack files.
        assert!(content.contains("com.apple.networkd.plist"));

        // deny-default still present.
        assert!(content.contains("(deny default)"));

        // Base Mach services still present.
        assert!(content.contains("com.apple.system.logger"));

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_profile_keychain() {
        let dir_off = std::env::temp_dir().join("arapuca-test-profile-keychain-off");
        let dir_on = std::env::temp_dir().join("arapuca-test-profile-keychain-on");
        let _ = std::fs::create_dir_all(&dir_off);
        let _ = std::fs::create_dir_all(&dir_on);

        // Keychain disabled: no securityd Mach lookup, no keychain files.
        let off = ProfileData {
            read_paths: vec!["/home/user/src".into()],
            write_paths: vec![],
            exec_paths: vec![],
            control_socket: None,
            llm_socket: None,
            allow_network: false,
            allow_keychain: false,
            tty: false,
        };
        let content_off =
            std::fs::read_to_string(generate_profile(&dir_off, &off).unwrap()).unwrap();
        assert!(!content_off.contains("com.apple.SecurityServer"));
        assert!(!content_off.contains("(allow file-read* (subpath \"/Library/Keychains\"))"));

        // Keychain enabled: securityd/ocspd Mach lookups + keychain files.
        let on = ProfileData {
            allow_keychain: true,
            ..off
        };
        let content_on = std::fs::read_to_string(generate_profile(&dir_on, &on).unwrap()).unwrap();
        assert!(
            content_on.contains("(allow mach-lookup (global-name \"com.apple.SecurityServer\"))")
        );
        assert!(content_on.contains("com.apple.ocspd"));
        assert!(content_on.contains("(allow file-read* (subpath \"/Library/Keychains\"))"));
        assert!(content_on.contains("(allow file-read* (subpath \"/private/var/db/mds\"))"));
        // deny-default is preserved.
        assert!(content_on.contains("(deny default)"));
        // With networking off, the keychain block supplies trustd itself.
        assert!(content_on.contains("(allow mach-lookup (global-name \"com.apple.trustd\"))"));

        // Keychain + network is a realistic production config. trustd is
        // granted by the network block, so the keychain block must not
        // emit it again (guards against duplicate Mach entries).
        let dir_both = std::env::temp_dir().join("arapuca-test-profile-keychain-net");
        let _ = std::fs::create_dir_all(&dir_both);
        let both = ProfileData {
            read_paths: vec!["/home/user/src".into()],
            write_paths: vec![],
            exec_paths: vec![],
            control_socket: None,
            llm_socket: None,
            allow_network: true,
            allow_keychain: true,
            tty: false,
        };
        let content_both =
            std::fs::read_to_string(generate_profile(&dir_both, &both).unwrap()).unwrap();
        let trustd_count = content_both
            .matches("(global-name \"com.apple.trustd\")")
            .count();
        assert_eq!(
            trustd_count, 1,
            "trustd must be granted exactly once when network and keychain are both on"
        );
        // Keychain files are still granted in the combined config.
        assert!(content_both.contains("(allow file-read* (subpath \"/Library/Keychains\"))"));

        let _ = std::fs::remove_dir_all(&dir_off);
        let _ = std::fs::remove_dir_all(&dir_on);
        let _ = std::fs::remove_dir_all(&dir_both);
    }

    #[test]
    fn test_generate_profile_proxy_only() {
        let dir = std::env::temp_dir().join("arapuca-test-profile-proxy");
        let _ = std::fs::create_dir_all(&dir);

        let data = ProfileData {
            read_paths: vec!["/home/user/src".into()],
            write_paths: vec!["/tmp/work".into()],
            exec_paths: vec![],
            control_socket: None,
            llm_socket: Some("/tmp/sock/proxy.sock".into()),
            allow_network: false,
            allow_keychain: false,
            tty: false,
        };

        let path = generate_profile(&dir, &data).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        // TCP outbound must be denied.
        assert!(
            !content.contains("network-outbound (remote tcp)"),
            "proxy-only mode must not allow TCP outbound"
        );

        // UDS to proxy must be allowed.
        assert!(
            content.contains(
                "(allow network-outbound (remote unix-socket (path-literal \"/tmp/sock/proxy.sock\")))"
            ),
            "proxy-only mode must allow UDS to proxy socket"
        );

        // Network Mach services must NOT be present.
        assert!(
            !content.contains("com.apple.dnssd.service"),
            "proxy-only mode must not allow DNS Mach services"
        );
        assert!(
            !content.contains("com.apple.trustd"),
            "proxy-only mode must not allow TLS Mach services"
        );

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }
}
