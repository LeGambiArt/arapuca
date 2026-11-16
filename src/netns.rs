//! Network namespace isolation.
//!
//! Probes whether `unshare --user --net --map-root-user` is available
//! on the current system. The actual namespace creation is done by the
//! platform sandbox (Linux) when launching subprocesses.

use std::process::Command;
use std::time::Duration;

/// Probe whether network namespace isolation works on this system.
///
/// Runs `unshare --user --net --map-root-user -- /bin/true` as a
/// subprocess. Returns `true` if it succeeds, `false` otherwise.
///
/// Some systems have the `unshare` binary but block the syscall via
/// kernel config or security modules. This probe uses the exact same
/// flags as the sandbox launch to ensure accuracy.
pub fn available() -> bool {
    let result = Command::new("unshare")
        .args(["--user", "--net", "--map-root-user", "--", "/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match result {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

/// Probe whether a user namespace with the current uid/gid mapped
/// 1:1 works on this system.
///
/// Runs `unshare --user --map-current-user -- /bin/true` — the exact
/// flags the `--userns` launch uses. Fails on hosts that disable
/// unprivileged user namespaces (kernel or LSM policy) and on
/// util-linux versions without `--map-current-user`, so the launcher
/// can fall back loudly instead of failing mid-run.
pub fn userns_current_user_available() -> bool {
    let result = Command::new("unshare")
        .args(["--user", "--map-current-user", "--", "/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match result {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

/// Probe whether mount namespace isolation works alongside netns.
///
/// Tests `unshare --user --net --mount --map-root-user -- /bin/true`.
/// Required for DNS capture (bind-mounting resolv.conf). Falls back
/// gracefully to netns-only if mount ns is unavailable.
pub fn mount_ns_available() -> bool {
    let result = Command::new("unshare")
        .args([
            "--user",
            "--net",
            "--mount",
            "--map-root-user",
            "--",
            "/bin/true",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match result {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

/// Timeout for the netns probe.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_does_not_panic() {
        // On most Linux systems this returns true.
        // On restricted systems or non-Linux, it returns false.
        // Either is valid — just verify no panic.
        let result = available();
        eprintln!("netns available: {result}");
    }
}
