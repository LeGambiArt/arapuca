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
