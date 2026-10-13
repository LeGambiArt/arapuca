//! Executable-bound compatibility checks for standalone Unix socket denial.

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::{Error, Result};

/// Keep the queried executable inode pinned through the actual wrapper exec.
pub(super) struct PinnedWrapper {
    fd: OwnedFd,
}

impl PinnedWrapper {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        // Reserve outside the extra-FD/internal-pipe remapping range.
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: successful duplication returns a descriptor we own.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    pub(super) fn fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    pub(super) fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.fd()))
    }

    pub(super) fn check(&self) -> Result<()> {
        self.check_with_timeout(Duration::from_secs(5))
    }

    fn check_with_timeout(&self, timeout: Duration) -> Result<()> {
        let fd = self.fd();
        let mut command = Command::new(self.path());
        command
            .arg("--wrapper-capabilities")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        // SAFETY: child-side setter only invokes async-signal-safe fcntl.
        unsafe { command.pre_exec(move || inherit_exec_fd(fd)) };
        let mut child = command.spawn()?;
        let result = (|| {
            let mut stdout = child
                .stdout
                .take()
                .ok_or_else(|| Error::Process("missing capability pipe".into()))?;
            let pipe_fd = stdout.as_raw_fd();
            let flags = unsafe { libc::fcntl(pipe_fd, libc::F_GETFL) };
            if flags < 0
                || unsafe { libc::fcntl(pipe_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let deadline = Instant::now() + timeout;
            let mut output = Vec::new();
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(Error::Validation(
                        "wrapper capability query timed out".into(),
                    ));
                }
                let poll_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
                let mut pfd = libc::pollfd {
                    fd: pipe_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: pfd points to a valid pollfd, nfds=1.
                let n = unsafe { libc::poll(&mut pfd, 1, poll_ms) };
                if n < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(e.into());
                }
                if n == 0 {
                    continue;
                }
                let mut buf = [0u8; 128];
                match stdout.read(&mut buf) {
                    Ok(0) => {
                        break;
                    }
                    Ok(n) => {
                        output.extend_from_slice(&buf[..n]);
                        if output.len() > 128 {
                            return Err(Error::Validation(
                                "oversized wrapper capability response".into(),
                            ));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if output != crate::wrapper::UNIX_SOCKET_CAPABILITY.as_bytes() {
                return Err(Error::Validation(
                    "wrapper does not support complete Unix socket denial".into(),
                ));
            }
            Ok(())
        })();
        // Kill the process group before reaping to avoid a PID reuse
        // window between waitpid and kill. Linux pid_max <= 4194304,
        // well within i32 range.
        unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
        let _ = child.kill();
        let _ = child.wait();
        result
    }
}

/// Preserve the pinned executable through exec; the trampoline closes it.
pub(super) fn inherit_exec_fd(fd: i32) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("wrapper");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn unsupported_malformed_and_oversized_responses_are_rejected() {
        for body in [
            "exit 1",
            "printf ''",
            "printf 'wrong\\n'",
            "i=0; while [ $i -lt 200 ]; do printf x; i=$((i+1)); done",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = fixture(dir.path(), body);
            let pinned = PinnedWrapper::open(&path).unwrap();
            assert!(pinned.check().is_err(), "{body}");
        }
    }

    #[test]
    fn capability_is_bound_to_the_original_inode() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path(), "printf 'arapuca unix-socket-denial-v1\\n'");
        let pinned = PinnedWrapper::open(&path).unwrap();
        std::fs::rename(&path, dir.path().join("old")).unwrap();
        fixture(dir.path(), "exit 1");
        assert!(pinned.check().is_ok());
    }

    #[test]
    fn hung_probe_is_killed_and_reaped() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path(), "while :; do :; done");
        let pinned = PinnedWrapper::open(&path).unwrap();
        let start = Instant::now();
        assert!(
            pinned
                .check_with_timeout(Duration::from_millis(30))
                .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
