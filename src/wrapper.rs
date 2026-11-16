//! Shared utilities for the wrapper execution path.
//!
//! Used by both the standalone `bin/arapuca` wrapper binary and the
//! selfexec trampoline (`selfexec.rs`). Extracted to avoid
//! duplication between the two paths.

use std::path::PathBuf;

/// Exact standalone-wrapper enforcement contract, independent of serde.
pub const UNIX_SOCKET_CAPABILITY: &str = "arapuca unix-socket-denial-v1\n";

/// Parse the trusted wrapper policy transport, rejecting malformed values.
pub fn deny_unix_sockets_from_env() -> crate::Result<bool> {
    match std::env::var("ARAPUCA_DENY_UNIX_SOCKETS") {
        Ok(v) if v == "1" => Ok(true),
        Ok(v) if v == "0" => Ok(false),
        Err(std::env::VarError::NotPresent) => Ok(false),
        _ => Err(crate::Error::Validation(
            "invalid ARAPUCA_DENY_UNIX_SOCKETS".into(),
        )),
    }
}

/// Validate retained resources before any internal helper socketpairs exist.
pub fn validate_unix_socket_policy(
    profile: &crate::Profile,
    direct_apply: bool,
) -> crate::Result<()> {
    profile.validate_unix_socket_policy()?;
    // The connect policy needs the unotify supervisor, which only
    // the launch topology spawns. Direct apply (arapuca_apply) has
    // no broker: an explicit DenyPrivileged request must fail
    // closed here instead of installing a policy that silently
    // does nothing — the C header documents unsupported requests
    // as errors.
    if direct_apply
        && profile.unix_socket_connect_policy == crate::UnixSocketConnectPolicy::DenyPrivileged
    {
        return Err(crate::Error::Validation(
            "unix socket connect policy requires the unotify supervisor and cannot be \
             enforced by direct apply; opt out with \
             unix_socket_connect_policy = AllowAll"
                .into(),
        ));
    }
    #[cfg(seccomp_supported)]
    if profile.deny_unix_sockets {
        if direct_apply {
            crate::seccomp::validate_single_threaded()?;
        }
        crate::seccomp::validate_no_retained_unix_resources()?;
    }
    let _ = direct_apply;
    Ok(())
}

/// Release the pinned wrapper descriptor after the trampoline exec.
#[cfg(target_os = "linux")]
pub fn close_wrapper_exec_fd() -> crate::Result<()> {
    if let Some(v) = std::env::var_os("ARAPUCA_WRAPPER_EXEC_FD") {
        let fd = v
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
            .filter(|&fd| fd >= 64)
            .ok_or_else(|| crate::Error::Validation("invalid wrapper exec FD".into()))?;
        // SAFETY: the launcher reserves this descriptor for the executable.
        if unsafe { libc::close(fd) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

/// Simple PATH lookup for a command name.
pub fn which(cmd: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let path_str = path_var.to_str()?;
    for dir in path_str.split(':') {
        let candidate = PathBuf::from(dir).join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Write an audit status line to the audit FD (if set).
///
/// Writes newline-delimited JSON. Errors are silently ignored — audit
/// is observability, not a security gate.
#[cfg(unix)]
pub fn audit_layer(fd: Option<i32>, layer: &str, ok: bool, error: Option<&str>) {
    let Some(fd) = fd else { return };
    let status = if ok { "applied" } else { "failed" };
    let json = if let Some(err) = error {
        let escaped = json_escape(err);
        format!(r#"{{"layer":"{layer}","status":"{status}","error":"{escaped}"}}"#)
    } else {
        format!(r#"{{"layer":"{layer}","status":"{status}"}}"#)
    };
    let line = format!("{json}\n");
    // SAFETY: fd is a valid descriptor from ARAPUCA_AUDIT_FD, buf/len valid.
    let _ = unsafe { libc::write(fd, line.as_ptr().cast::<libc::c_void>(), line.len()) };
}

/// Escape a string for JSON (RFC 8259): backslash, double-quote,
/// and all control characters below U+0020.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < '\u{0020}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Write a message to stderr using raw libc (async-signal-safe).
#[cfg(unix)]
pub fn write_stderr(msg: &str) {
    let _ = unsafe { libc::write(2, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
}

/// Bind-mount a custom resolv.conf with `nameserver 127.0.0.1` over
/// `/etc/resolv.conf` for DNS capture. Called inside the mount
/// namespace before Landlock.
///
/// Uses PID in the temp filename to avoid races under concurrent
/// launches. Remounts read-only after the bind mount.
/// Returns true on success, false on failure.
#[cfg(target_os = "linux")]
pub fn override_resolv_conf() -> bool {
    let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
    let pid = std::process::id();
    let mut rand_buf = [0u8; 8];
    let rand_hex = if unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            rand_buf.as_mut_ptr(),
            rand_buf.len(),
            0u32,
        )
    } == 8
    {
        rand_buf.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    } else {
        String::from("00000000")
    };
    let path = format!("{tmpdir}/.arapuca-resolv-{pid}-{rand_hex}.conf");

    // O_EXCL prevents symlink-following attacks on the temp file.
    use std::io::Write;
    let mut f = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => {
            write_stderr("arapuca: failed to create resolv.conf override\n");
            return false;
        }
    };
    if f.write_all(b"nameserver 127.0.0.1\n").is_err() {
        write_stderr("arapuca: failed to write resolv.conf override\n");
        let _ = std::fs::remove_file(&path);
        return false;
    }
    drop(f);

    let src = match std::ffi::CString::new(path.as_str()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let dst = match std::ffi::CString::new("/etc/resolv.conf") {
        Ok(s) => s,
        Err(_) => return false,
    };

    let ret = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        write_stderr(&format!(
            "arapuca: resolv.conf bind mount failed: {}\n",
            std::io::Error::last_os_error()
        ));
        let _ = std::fs::remove_file(&path);
        return false;
    }

    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        write_stderr("arapuca: resolv.conf remount-ro failed\n");
    }

    let _ = std::fs::remove_file(&path);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escape_plain() {
        assert_eq!(json_escape("hello world"), "hello world");
    }

    #[test]
    fn json_escape_quotes_and_backslash() {
        assert_eq!(json_escape(r#"say "hi""#), r#"say \"hi\""#);
        assert_eq!(json_escape(r"back\slash"), r"back\\slash");
    }

    #[test]
    fn json_escape_control_characters() {
        assert_eq!(json_escape("tab\there"), "tab\\u0009here");
        assert_eq!(json_escape("new\nline"), "new\\u000aline");
        assert_eq!(json_escape("\x00null"), "\\u0000null");
        assert_eq!(json_escape("\x1f"), "\\u001f");
    }

    #[test]
    fn json_escape_mixed() {
        assert_eq!(
            json_escape("err: \"bad\\path\"\n"),
            "err: \\\"bad\\\\path\\\"\\u000a"
        );
    }

    #[test]
    fn json_escape_unicode_passthrough() {
        assert_eq!(json_escape("café ☕ 日本語"), "café ☕ 日本語");
    }

    #[test]
    fn json_escape_empty() {
        assert_eq!(json_escape(""), "");
    }

    #[cfg(unix)]
    #[test]
    fn which_finds_known_command() {
        assert!(which("sh").is_some());
    }

    #[test]
    fn which_returns_none_for_missing() {
        assert!(which("__nonexistent_binary_42__").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn which_result_is_file() {
        if let Some(path) = which("sh") {
            assert!(path.is_file());
        }
    }
}

/// Scrub root-derived capabilities for the process about to be
/// exec'd as the sandboxed target.
///
/// `SECBIT_NOROOT` suppresses the full-capability grant the kernel
/// applies at exec for uid 0 in a user namespace; `SECBIT_NOROOT_-
/// LOCKED` makes it irrevocable. Without this, a target running as
/// root inside `unshare --user --map-root-user` retains
/// `CAP_SYS_PTRACE` in the shared namespace, which bypasses both
/// `PR_SET_DUMPABLE=0` and Yama on every same-namespace process —
/// including the unotify supervisor whose seccomp allowlist permits
/// `connect()`, i.e. a memory-corrupted supervisor is a policy
/// bypass. The scrub makes the target capless at the exec boundary.
///
/// The prctl can fail with `EPERM` for a process that holds no
/// capabilities and is not uid 0 in its user namespace — exactly the
/// processes for which the suppressed grant does not exist. That
/// case is a no-op; every other failure is fatal (fail-closed).
#[cfg(target_os = "linux")]
pub fn scrub_capabilities_for_exec() -> Result<(), String> {
    const PR_SET_SECUREBITS: libc::c_int = 28;
    const PR_GET_SECUREBITS: libc::c_int = 29;
    const SECBIT_NOROOT: libc::c_ulong = 1 << 0;
    const SECBIT_NOROOT_LOCKED: libc::c_ulong = 1 << 1;
    // PR_CAP_AMBIENT_CLEAR_ALL needs no privilege and must run FIRST:
    // SECBIT_NOROOT does not touch the ambient set, so an ambient
    // CAP_SETPCAP would let the prctl below succeed while every other
    // ambient capability (CAP_SYS_PTRACE included) survives into the
    // target — the opposite of "capless at exec".
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
    // SAFETY: prctl with scalar arguments; no pointers involved.
    let ret = unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        // EINVAL is the kernel's answer when ambient capabilities are
        // unsupported (pre-4.3): nothing to clear there.
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(format!("PR_CAP_AMBIENT_CLEAR_ALL: {err}"));
        }
    }

    // OR the bits in instead of replacing the whole set: overwriting
    // would silently clear unlocked bits the parent set (e.g.
    // SECBIT_NO_CAP_AMBIENT_RAISE under systemd) and EPERM when the
    // parent locked any other bit.
    // SAFETY: prctl with scalar arguments; no pointers involved.
    let current = unsafe { libc::prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) };
    let wanted = SECBIT_NOROOT | SECBIT_NOROOT_LOCKED;
    if current >= 0 && (current as libc::c_ulong & wanted) == wanted {
        return Ok(());
    }
    // SAFETY: prctl with scalar arguments; no pointers involved.
    let ret = unsafe {
        libc::prctl(
            PR_SET_SECUREBITS,
            (current.max(0) as libc::c_ulong | wanted) as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if ret == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EPERM) && root_grant_absent() {
        return Ok(());
    }
    Err(format!("PR_SET_SECUREBITS: {err}"))
}

/// True when the exec-time root capability grant cannot apply to
/// this process: not uid 0 in the current user namespace and no
/// permitted capabilities. Uses `capget` rather than
/// `/proc/self/status` because the scrub runs after Landlock, which
/// does not grant /proc.
#[cfg(target_os = "linux")]
fn root_grant_absent() -> bool {
    // The exec-time root grant only exists for a root uid, and only
    // if the bounding set still carries anything that could be
    // re-gained. The permitted set is the wrong signal: it is empty
    // for a root container with cap-drop ALL (which still has the
    // grant masked, but nothing to gain) and non-empty for a non-root
    // service with AmbientCapabilities (which can never gain the
    // root grant at all). Both of those must count as "grant absent"
    // or every launch in them fails.
    // SAFETY: geteuid/getuid take no arguments.
    if unsafe { libc::geteuid() } == 0 || unsafe { libc::getuid() } == 0 {
        // Root uid with an empty permitted set under
        // no-new-privs: nothing can be gained at exec — the kernel
        // intersects file-derived capabilities with the OLD
        // permitted set (cap_bprm_creds_from_file), and NNP is set
        // before this runs. Observed in the wild: root containers
        // and the viveiro agent harness run exactly this shape
        // (uid 0, CapPrm=0, CapBnd full) and every launch failed.
        // SAFETY: prctl with scalar arguments.
        let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1;
        #[cfg(target_os = "linux")]
        if nnp && permitted_set_empty() {
            return true;
        }
        // Otherwise the grant exists unless the bounding set is
        // empty — then no capability can ever be regained.
        // CAP_LAST_CAP is not in libc. 40 (CAP_CHECKPOINT_RESTORE)
        // is the last capability on current kernels; read one past
        // it so the loop covers everything — PR_CAPBSET_READ answers
        // EINVAL above the last capability, treated as "not
        // present".
        for cap in 0..=41 {
            // SAFETY: prctl PR_CAPBSET_READ with a plain capability
            // number.
            let r = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
            if r > 0 {
                return false;
            }
        }
        return true;
    }
    // Non-root uid: no root grant can ever apply — a setuid-root
    // exec would need a root uid. Under no-new-privs the exec-time
    // gain is intersected with the old permitted set, so a
    // capability held in the permitted set can survive a
    // file-capabilities exec; that is a narrower residual than the
    // old permitted==0 test, which refused every launch for
    // non-root services with AmbientCapabilities.
    // Testing the ambient path itself needs a capability in the
    // permitted set, which the unprivileged test runner does not
    // have; the uid logic is what the unprivileged tests pin.
    true
}

/// Whether this process's permitted capability set is empty.
#[cfg(target_os = "linux")]
fn permitted_set_empty() -> bool {
    // SAFETY: capget with stack structs of the ABI shapes from
    // include/uapi/linux/capability.h; pid 0 means "this process".
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut hdr = CapHeader {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: syscall with valid pointers to live stack structs.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut hdr as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    ret == 0 && data.iter().all(|d| d.permitted == 0)
}

#[cfg(all(test, target_os = "linux"))]
mod securebits_tests {
    use super::*;

    #[test]
    fn scrub_succeeds_or_noops_for_unprivileged_caller() {
        // As the unprivileged test user the prctl either succeeds
        // (setting the bits is permitted) or returns EPERM with the
        // root grant absent — both acceptable; anything else fails.
        scrub_capabilities_for_exec().expect("scrub must succeed or no-op");
    }

    #[test]
    fn root_grant_absent_for_unprivileged_test_user() {
        // The test runner is unprivileged: euid != 0 and CapPrm is
        // empty, so the grant is absent. (Skipped implicitly when run
        // as root, where euid == 0 makes the predicate false.)
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        assert!(root_grant_absent());
    }
}

/// Drop all capabilities (permitted, effective, inheritable) for the
/// calling process.
///
/// Used by internal helper children (pidns relay, bridge, DNS,
/// connect proxy) forked from a capability-bearing wrapper in
/// `--map-root-user` modes: a capful, `/proc`-reachable helper is a
/// memory-corruption pivot for anything that can open its
/// `/proc/<pid>/mem` — capabilities bypass `PR_SET_DUMPABLE=0` and
/// Yama. These helpers never exec and never need capabilities.
///
/// Dropping is unprivileged (only raising requires CAP_SETPCAP);
/// for an already-capless process this is a no-op.
#[cfg(target_os = "linux")]
pub fn drop_capabilities() -> Result<(), String> {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut hdr = CapHeader {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    // All-zero sets: drop everything.
    let data = [CapData::default(); 2];
    // SAFETY: capset with stack structs of the ABI shapes from
    // include/uapi/linux/capability.h; pid 0 means "this process".
    let ret = unsafe { libc::syscall(libc::SYS_capset, &mut hdr as *mut CapHeader, data.as_ptr()) };
    if ret != 0 {
        return Err(format!("capset: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod capdrop_tests {
    use super::*;

    #[test]
    fn drop_capabilities_succeeds_unprivileged() {
        drop_capabilities().expect("capset drop must succeed");
    }
}
