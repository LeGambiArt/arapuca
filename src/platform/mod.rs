//! Platform-specific sandbox implementations.
//!
//! Each platform provides a [`Sandbox`] implementation that coordinates
//! the available isolation primitives (Landlock, seccomp, cgroups, netns
//! on Linux; sandbox-exec on macOS; degraded fallback elsewhere).

#[cfg(unix)]
use std::os::unix::io::{FromRawFd, RawFd};
#[cfg(unix)]
use std::process::{Command, Stdio};

use crate::{Config, process::Process};

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(unix)]
mod fd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(target_os = "linux", feature = "microvm"))]
pub(crate) mod microvm;
#[cfg(all(target_os = "linux", feature = "microvm"))]
pub(crate) mod microvm_net;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod other;
#[cfg(target_os = "windows")]
pub(crate) mod windows;
#[cfg(target_os = "linux")]
mod wrapper_exec;

#[cfg(target_os = "windows")]
pub use self::windows::Windows;
#[cfg(target_os = "macos")]
pub use darwin::Darwin;
#[cfg(target_os = "linux")]
pub use linux::Linux;
#[cfg(all(target_os = "linux", feature = "microvm"))]
pub use microvm::MicroVm;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub use other::Other;

/// Platform-specific sandbox implementation.
///
/// Coordinates OS-level isolation primitives to launch sandboxed
/// subprocesses.
pub trait Sandbox: Send + Sync {
    /// Launch a sandboxed subprocess with the given config.
    ///
    /// The subprocess inherits only explicitly configured FDs/handles
    /// and a minimal environment.
    fn launch(&self, cfg: &Config, cmd: &str, args: &[&str]) -> crate::Result<Process>;

    /// Reports whether this sandbox implementation is available on
    /// the current platform. Returns an error describing why if not.
    fn available(&self) -> crate::Result<()>;

    /// Probes whether network namespace isolation works on this system.
    fn netns_available(&self) -> bool;

    /// Reports whether cgroups v2 resource limits are available.
    fn cgroups_available(&self) -> bool;
}

/// Duplicate an optional FD with CLOEXEC and wire it to a Command's
/// stdin, stdout, or stderr. If `fd` is `None`, inherits from parent.
///
/// FDs 0, 1, 2 are valid inputs — `F_DUPFD_CLOEXEC` creates a new FD
/// without disturbing the parent's original.
#[cfg(unix)]
pub(crate) fn setup_stdio(
    command: &mut Command,
    fd: Option<RawFd>,
    stream: &str,
    setter: fn(&mut Command, Stdio) -> &mut Command,
) -> crate::Result<()> {
    match fd {
        Some(fd) => {
            // SAFETY: F_DUPFD_CLOEXEC on a valid fd returns a new fd
            // we own, with CLOEXEC set atomically.
            let duped = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
            if duped == -1 {
                return Err(crate::Error::Process(format!(
                    "dup {stream} fd: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: duped is a valid fd we own (verified != -1 above).
            setter(command, unsafe { Stdio::from_raw_fd(duped) });
        }
        None => {
            setter(command, Stdio::inherit());
        }
    }
    Ok(())
}

/// Create the appropriate sandbox for the current platform.
#[cfg(target_os = "linux")]
pub fn new() -> crate::Result<Linux> {
    Linux::new()
}

/// Create the appropriate sandbox for the current platform (macOS).
#[cfg(target_os = "macos")]
pub fn new() -> crate::Result<Darwin> {
    Darwin::new()
}

/// Create the appropriate sandbox for the current platform (Windows).
#[cfg(target_os = "windows")]
pub fn new() -> crate::Result<Windows> {
    Windows::new()
}

/// Create the appropriate sandbox for the current platform (fallback).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn new() -> crate::Result<Other> {
    Ok(Other)
}

/// Create a boxed sandbox for the C FFI (type-erased for platform agnosticism).
pub fn new_boxed() -> crate::Result<Box<dyn Sandbox>> {
    Ok(Box::new(new()?))
}
