//! Shared FD helpers for platform sandbox implementations.
//!
//! Provides extra_fds validation and the two-pass FD remapping used
//! inside pre_exec closures.

use std::os::unix::io::RawFd;

use crate::{Config, Error};

// Upper bound on caller-supplied extra FDs. The remap uses a Vec
// (via ManuallyDrop) so any count works; 16 is a practical limit
// that bounds pre_exec syscall overhead (~96 calls at n=16).
const MAX_EXTRA_FDS: usize = 16;

pub(super) fn validate_extra_fds(fds: &[RawFd], cfg: &Config) -> crate::Result<()> {
    if fds.len() > MAX_EXTRA_FDS {
        return Err(Error::Validation(format!(
            "extra_fds: too many FDs ({}, max {MAX_EXTRA_FDS})",
            fds.len()
        )));
    }
    for (i, &fd) in fds.iter().enumerate() {
        if fd < 0 {
            return Err(Error::Validation(format!(
                "extra_fds[{i}]: negative FD {fd}"
            )));
        }
        if fd <= 2 {
            return Err(Error::Validation(format!(
                "extra_fds[{i}]: FD {fd} is stdin/stdout/stderr \
                 (use cfg.stdin/stdout/stderr instead)"
            )));
        }
        if fds[..i].contains(&fd) {
            return Err(Error::Validation(format!(
                "extra_fds[{i}]: duplicate FD {fd}"
            )));
        }
        let stdio_fds = [cfg.stdin, cfg.stdout, cfg.stderr];
        if stdio_fds.contains(&Some(fd)) {
            return Err(Error::Validation(format!(
                "extra_fds[{i}]: FD {fd} overlaps with stdio config"
            )));
        }
    }
    Ok(())
}

/// Remap extra FDs to deterministic positions (3, 4, ...).
///
/// Must only be called inside a pre_exec closure (between fork and
/// exec). All operations are async-signal-safe. The ManuallyDrop
/// wrapper on the caller's Vec prevents free() from running in the
/// child process.
///
/// Uses a two-pass approach to avoid FD collisions when source FDs
/// overlap with the target range [3..3+N):
/// - Phase 1: evacuate sources in the target range to high FDs.
/// - Phase 2: dup2 to final positions and clear CLOEXEC.
pub(super) unsafe fn remap_fds(
    fds: &mut std::mem::ManuallyDrop<Vec<RawFd>>,
) -> std::io::Result<()> {
    let fds = fds.as_mut_slice();
    let base = 3i32;
    let ceiling = base + fds.len() as i32;

    // Phase 1: evacuate source FDs in [base..ceiling) to above
    // the target range.
    for slot in fds.iter_mut() {
        if *slot >= base && *slot < ceiling {
            // SAFETY: F_DUPFD_CLOEXEC returns a new FD >= ceiling
            // that we own, with CLOEXEC set atomically.
            let high = unsafe { libc::fcntl(*slot, libc::F_DUPFD_CLOEXEC, ceiling) };
            if high == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // Non-fatal: original has CLOEXEC, kernel cleans up at exec.
            unsafe { libc::close(*slot) };
            *slot = high;
        }
    }

    // Phase 2: place into final positions.
    for (i, &fd) in fds.iter().enumerate() {
        let target = base + i as i32;
        if fd != target {
            // SAFETY: dup2 atomically copies fd to target.
            if unsafe { libc::dup2(fd, target) } == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // Non-fatal: source has CLOEXEC, kernel cleans up at exec.
            unsafe { libc::close(fd) };
        }
        // Clear CLOEXEC so the FD survives exec.
        // SAFETY: fcntl F_GETFD/F_SETFD are simple flag operations.
        let flags = unsafe { libc::fcntl(target, libc::F_GETFD) };
        if flags == -1 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_config() -> Config {
        Config {
            profile: crate::Profile::default(),
            socket_dir: PathBuf::from("/tmp"),
            task_id: "test".into(),
            phase: String::new(),
            work_dir: None,
            stdin: None,
            stdout: None,
            stderr: None,
            extra_fds: vec![],
            tty: false,
            network_proxy_socket: None,
            #[cfg(target_os = "linux")]
            allowed_hosts: Vec::new(),
            env: vec![],
            audit_sink: None,
            audit_verbosity: crate::audit::AuditVerbosity::default(),
            audit_principal: None,
            audit_correlation_id: None,
        }
    }

    #[test]
    fn validate_empty() {
        assert!(validate_extra_fds(&[], &test_config()).is_ok());
    }

    #[test]
    fn validate_valid_fds() {
        assert!(validate_extra_fds(&[5, 10, 20], &test_config()).is_ok());
    }

    #[test]
    fn validate_fd_three_ok() {
        assert!(validate_extra_fds(&[3], &test_config()).is_ok());
    }

    #[test]
    fn validate_negative_fd() {
        let err = validate_extra_fds(&[-1], &test_config()).unwrap_err();
        assert!(err.to_string().contains("negative FD"));
    }

    #[test]
    fn validate_fd_zero() {
        let err = validate_extra_fds(&[0], &test_config()).unwrap_err();
        assert!(err.to_string().contains("stdin/stdout/stderr"));
    }

    #[test]
    fn validate_fd_one() {
        let err = validate_extra_fds(&[1], &test_config()).unwrap_err();
        assert!(err.to_string().contains("stdin/stdout/stderr"));
    }

    #[test]
    fn validate_fd_two() {
        let err = validate_extra_fds(&[2], &test_config()).unwrap_err();
        assert!(err.to_string().contains("stdin/stdout/stderr"));
    }

    #[test]
    fn validate_duplicate() {
        let err = validate_extra_fds(&[5, 5], &test_config()).unwrap_err();
        assert!(err.to_string().contains("duplicate FD 5"));
    }

    #[test]
    fn validate_stdio_overlap() {
        let mut cfg = test_config();
        cfg.stdin = Some(7);
        let err = validate_extra_fds(&[7], &cfg).unwrap_err();
        assert!(err.to_string().contains("overlaps with stdio"));
    }

    #[test]
    fn validate_too_many() {
        let fds: Vec<RawFd> = (3..3 + MAX_EXTRA_FDS as i32 + 1).collect();
        let err = validate_extra_fds(&fds, &test_config()).unwrap_err();
        assert!(err.to_string().contains("too many FDs"));
    }

    #[test]
    fn validate_exactly_max() {
        let fds: Vec<RawFd> = (3..3 + MAX_EXTRA_FDS as i32).collect();
        assert!(validate_extra_fds(&fds, &test_config()).is_ok());
    }

    // ── remap_fds tests ───────────────────────────────────────────
    //
    // remap_fds overwrites FDs 3, 4, ... in the calling process, so
    // these tests fork a child to isolate the FD table. The child
    // calls remap_fds, reads from the remapped targets, and reports
    // success via _exit(42) or failure via _exit(1).

    fn make_pipe() -> (RawFd, RawFd) {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        (fds[0], fds[1])
    }

    fn run_remap_test(test_fn: fn()) -> (bool, i32) {
        // SAFETY: fork is safe in single-threaded test context.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            test_fn();
            unsafe { libc::_exit(0) };
        }
        let mut status: libc::c_int = 0;
        assert!(unsafe { libc::waitpid(pid, &mut status, 0) } > 0);
        if libc::WIFEXITED(status) {
            (true, libc::WEXITSTATUS(status))
        } else {
            (false, libc::WTERMSIG(status))
        }
    }

    #[test]
    fn remap_high_fds() {
        let (exited, code) = run_remap_test(|| {
            let (r1, w1) = make_pipe();
            let (r2, w2) = make_pipe();
            unsafe { libc::write(w1, b"AA".as_ptr().cast(), 2) };
            unsafe { libc::write(w2, b"BB".as_ptr().cast(), 2) };
            unsafe { libc::close(w1) };
            unsafe { libc::close(w2) };

            let mut fds = std::mem::ManuallyDrop::new(vec![r1, r2]);
            if unsafe { remap_fds(&mut fds) }.is_err() {
                unsafe { libc::_exit(1) };
            }

            let mut buf = [0u8; 2];
            if unsafe { libc::read(3, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"AA" {
                unsafe { libc::_exit(1) };
            }
            if unsafe { libc::read(4, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"BB" {
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::_exit(42) };
        });
        assert!(exited);
        assert_eq!(code, 42, "remap of high FDs failed");
    }

    #[test]
    fn remap_source_in_target_range() {
        let (exited, code) = run_remap_test(|| {
            // Close FDs 3-6 in the child so pipe() allocates them.
            for fd in 3..=6 {
                unsafe { libc::close(fd) };
            }
            // pipe() returns the lowest available FDs: (3,4) and (5,6).
            let (r1, w1) = make_pipe(); // r1=3, w1=4
            let (r2, w2) = make_pipe(); // r2=5, w2=6
            unsafe { libc::write(w1, b"XX".as_ptr().cast(), 2) };
            unsafe { libc::write(w2, b"YY".as_ptr().cast(), 2) };
            unsafe { libc::close(w1) };
            unsafe { libc::close(w2) };

            // r1=3, r2=5. For a 2-element remap, target range is [3,5).
            // FD 3 is in range and must be evacuated. FD 5 is not.
            let mut fds = std::mem::ManuallyDrop::new(vec![r1, r2]);
            if unsafe { remap_fds(&mut fds) }.is_err() {
                unsafe { libc::_exit(1) };
            }

            let mut buf = [0u8; 2];
            if unsafe { libc::read(3, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"XX" {
                unsafe { libc::_exit(2) };
            }
            if unsafe { libc::read(4, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"YY" {
                unsafe { libc::_exit(3) };
            }
            unsafe { libc::_exit(42) };
        });
        assert!(exited);
        assert_eq!(code, 42, "remap with source in target range failed");
    }

    #[test]
    fn remap_swap() {
        let (exited, code) = run_remap_test(|| {
            // Close FDs 3-6 so pipe() allocates them predictably.
            for fd in 3..=6 {
                unsafe { libc::close(fd) };
            }
            let (r1, w1) = make_pipe(); // r1=3, w1=4
            let (r2, w2) = make_pipe(); // r2=5, w2=6
            unsafe { libc::write(w1, b"11".as_ptr().cast(), 2) };
            unsafe { libc::write(w2, b"22".as_ptr().cast(), 2) };
            unsafe { libc::close(w1) };
            unsafe { libc::close(w2) };

            // Swap: place r2 (data "22") at FD 3, r1 (data "11") at FD 4.
            // For a 2-element remap, fds[0]->target 3, fds[1]->target 4.
            // r2=5, r1=3. fds=[5, 3]: target 3 gets r2's data ("22"),
            // target 4 gets r1's data ("11"). FD 3 is in range [3,5)
            // and must be evacuated.
            let mut fds = std::mem::ManuallyDrop::new(vec![r2, r1]);
            if unsafe { remap_fds(&mut fds) }.is_err() {
                unsafe { libc::_exit(1) };
            }

            let mut buf = [0u8; 2];
            if unsafe { libc::read(3, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"22" {
                unsafe { libc::_exit(2) };
            }
            if unsafe { libc::read(4, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"11" {
                unsafe { libc::_exit(3) };
            }
            unsafe { libc::_exit(42) };
        });
        assert!(exited);
        assert_eq!(code, 42, "remap swap failed");
    }

    #[test]
    fn remap_single_fd() {
        let (exited, code) = run_remap_test(|| {
            let (r, w) = make_pipe();
            unsafe { libc::write(w, b"OK".as_ptr().cast(), 2) };
            unsafe { libc::close(w) };

            let mut fds = std::mem::ManuallyDrop::new(vec![r]);
            if unsafe { remap_fds(&mut fds) }.is_err() {
                unsafe { libc::_exit(1) };
            }

            let mut buf = [0u8; 2];
            if unsafe { libc::read(3, buf.as_mut_ptr().cast(), 2) } != 2 || &buf != b"OK" {
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::_exit(42) };
        });
        assert!(exited);
        assert_eq!(code, 42, "remap single FD failed");
    }

    #[test]
    fn remap_clears_cloexec() {
        let (exited, code) = run_remap_test(|| {
            let (r, w) = make_pipe();
            // Set CLOEXEC on the read end.
            unsafe { libc::fcntl(r, libc::F_SETFD, libc::FD_CLOEXEC) };
            unsafe { libc::write(w, b"CE".as_ptr().cast(), 2) };
            unsafe { libc::close(w) };

            let mut fds = std::mem::ManuallyDrop::new(vec![r]);
            if unsafe { remap_fds(&mut fds) }.is_err() {
                unsafe { libc::_exit(1) };
            }

            let flags = unsafe { libc::fcntl(3, libc::F_GETFD) };
            if flags == -1 || (flags & libc::FD_CLOEXEC) != 0 {
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::_exit(42) };
        });
        assert!(exited);
        assert_eq!(code, 42, "CLOEXEC should be cleared after remap");
    }
}

// The sweep below is Linux-only: it is built on close_range(2), which
// no other platform in this crate has, and every caller is already
// behind #[cfg(target_os = "linux")]. Gating the items themselves
// keeps a non-Linux build from seeing references to symbols that do
// not exist there.

/// Number of descriptors the launcher may hand to the target: the
/// caller's `extra_fds`, remapped to `[3, 3+E)` by [`remap_fds`].
///
/// The internal pipes the launcher adds (audit, DNS audit, unotify,
/// pid report, cgroup sync) sit *above* that window and are consumed
/// by the wrapper itself, never by the target.
#[cfg(target_os = "linux")]
pub(crate) const TARGET_FD_BASE: i32 = 3;

/// `ARAPUCA_TARGET_FDS` carries `E` to the wrapper. The wrapper path is
/// only reachable with `ARAPUCA_WRAPPER=1`, so the variable is required
/// there and a missing value is a version-skew error, never a silent
/// "sweep everything".
#[cfg(target_os = "linux")]
pub(crate) const TARGET_FDS_ENV: &str = "ARAPUCA_TARGET_FDS";

/// Upper bound on `E`, mirroring [`MAX_EXTRA_FDS`]. Kept in sync by the
/// unit test below.
#[cfg(target_os = "linux")]
pub(crate) const MAX_TARGET_FDS: i32 = MAX_EXTRA_FDS as i32;

/// How [`sweep_inherited`] disposes of the descriptors it does not keep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(target_os = "linux")]
pub(crate) enum SweepMode {
    /// Set close-on-exec, leaving the descriptors usable. Used where the
    /// final keep-set is not known yet (the launcher, before
    /// [`remap_fds`] decides which descriptors survive).
    MarkCloexec,
    /// Close them outright. Used immediately before `execve`.
    HardClose,
}

/// Mark or close every descriptor `>= TARGET_FD_BASE` outside
/// `[TARGET_FD_BASE, keep_end)`.
///
/// Prefers `close_range(2)`, which needs no bound and reaches the whole
/// descriptor space. Falls back to a blind `fcntl`/`close` loop bounded
/// by `nofile_bound` on kernels older than 5.9, or where
/// `CLOSE_RANGE_CLOEXEC` is unsupported (5.9/5.10).
///
/// Async-signal-safe: only `syscall`, `fcntl` and `close` are used, so
/// this may run inside a `pre_exec` closure. The caller must pass a
/// `nofile_bound` captured *before* any descriptor limit is lowered —
/// descriptors above a lowered bound would otherwise escape the
/// fallback.
#[cfg(target_os = "linux")]
pub(crate) fn sweep_inherited(
    keep_end: i32,
    mode: SweepMode,
    nofile_bound: i32,
) -> std::io::Result<()> {
    let keep_end = keep_end.max(TARGET_FD_BASE);
    let flags = match mode {
        SweepMode::MarkCloexec => CLOSE_RANGE_CLOEXEC,
        SweepMode::HardClose => 0,
    };

    // Everything above the keep window — the part a fixed 1024-style
    // ceiling used to miss.
    match close_range(keep_end as u32, u32::MAX, flags) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Fall back on ANY failure, matching
            // bridge::close_fds_except: seccomp profiles that EPERM
            // unknown syscalls (older Docker/snap confinement,
            // systemd SystemCallFilter=) answer EPERM for
            // close_range, and aborting the launch there turns a
            // complete fallback sweep into a hard failure.
            fallback_sweep(keep_end, nofile_bound, mode);
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
const CLOSE_RANGE_CLOEXEC: u32 = 4;

#[cfg(target_os = "linux")]
fn close_range(first: u32, last: u32, flags: u32) -> std::io::Result<()> {
    if first > last {
        return Ok(());
    }
    // SAFETY: close_range takes three plain integers and touches no
    // caller memory.
    let ret = unsafe { libc::syscall(libc::SYS_close_range, first, last, flags) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
/// Blind sweep used when `close_range(2)` is unavailable.
///
/// A `/proc/self/fd` enumeration is not an option here: it allocates,
/// which is not async-signal-safe after `fork`, and the wrapper paths
/// run under Landlock, which denies `/proc` (see `pidns.rs`).
#[cfg(target_os = "linux")]
fn fallback_sweep(keep_end: i32, nofile_bound: i32, mode: SweepMode) {
    let end = nofile_bound.max(keep_end);
    for fd in keep_end..end {
        match mode {
            SweepMode::HardClose => {
                // SAFETY: closing an unopened descriptor is a no-op
                // (EBADF), so the result is intentionally ignored.
                unsafe { libc::close(fd) };
            }
            SweepMode::MarkCloexec => {
                // SAFETY: F_GETFD/F_SETFD are plain flag operations.
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                if flags >= 0 {
                    // SAFETY: same as above.
                    unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
                }
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod sweep_tests {
    use super::*;

    fn pipe2() -> (i32, i32) {
        let mut fds = [0i32; 2];
        // SAFETY: pipe2 with a valid two-element array.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), 0) }, 0);
        (fds[0], fds[1])
    }

    /// Duplicate `fd` onto the lowest *free* descriptor `>= min`.
    ///
    /// Never use a fixed number here: the test process is shared with
    /// every other test, and `dup2` onto an occupied descriptor closes
    /// whatever was there.
    fn dup_at_least(fd: i32, min: i32) -> i32 {
        // SAFETY: F_DUPFD with a valid descriptor and bound.
        let out = unsafe { libc::fcntl(fd, libc::F_DUPFD, min) };
        assert!(out >= min, "F_DUPFD({min}) -> {out}");
        out
    }

    /// Run `body` in a forked child and report whether it returned true.
    ///
    /// A sweep touches the whole descriptor space of the process it runs
    /// in (and only that process), so it must not run in the shared test
    /// process: closing a sibling test's descriptor is exactly the bug
    /// these functions exist to prevent.
    fn in_forked_child(body: impl FnOnce() -> bool) -> bool {
        // SAFETY: fork in a test; the child runs only syscalls and
        // `_exit`, so no allocation or locking happens after fork.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            let ok = body();
            // SAFETY: _exit skips atexit handlers and buffer flushes.
            unsafe { libc::_exit(i32::from(!ok)) };
        }
        let mut status = 0i32;
        // SAFETY: waitpid on the child just forked.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    fn fd_flags(fd: i32) -> i32 {
        // SAFETY: plain flag query.
        unsafe { libc::fcntl(fd, libc::F_GETFD) }
    }

    #[test]
    fn target_fd_bound_tracks_the_extra_fd_bound() {
        // The wrapper validates ARAPUCA_TARGET_FDS against MAX_TARGET_FDS;
        // if the extra-fd ceiling moved without this one, a launcher could
        // pass a window the wrapper rejects.
        assert_eq!(MAX_TARGET_FDS, MAX_EXTRA_FDS as i32);
    }

    #[test]
    fn mark_cloexec_keeps_descriptors_usable() {
        assert!(
            in_forked_child(|| {
                let (_r, w) = pipe2();
                // Two descriptors well above the keep window.
                let kept = dup_at_least(w, 64);
                let other = dup_at_least(w, kept + 1);
                if sweep_inherited(TARGET_FD_BASE, SweepMode::MarkCloexec, 1024).is_err() {
                    return false;
                }
                // Still open (flagged, not closed) and flagged.
                fd_flags(kept) >= 0
                    && fd_flags(other) >= 0
                    && fd_flags(kept) & libc::FD_CLOEXEC != 0
                    && fd_flags(other) & libc::FD_CLOEXEC != 0
            }),
            "a marking sweep must set CLOEXEC without closing anything"
        );
    }

    #[test]
    fn hard_close_removes_everything_outside_the_window() {
        assert!(
            in_forked_child(|| {
                let (_r, w) = pipe2();
                // `keep_end` sits just above the pipe's own descriptors:
                // nothing survives, including the descriptor far above it.
                let far = dup_at_least(w, 512);
                if sweep_inherited(TARGET_FD_BASE, SweepMode::HardClose, 1024).is_err() {
                    return false;
                }
                fd_flags(far) == -1
            }),
            "descriptors outside the keep window must be closed"
        );
    }

    #[test]
    fn hard_close_spares_the_keep_window() {
        assert!(
            in_forked_child(|| {
                let (_r, w) = pipe2();
                let keep_end = dup_at_least(w, 64);
                let kept = keep_end - 1;
                // SAFETY: dup2 onto the free slot just below the window end.
                if unsafe { libc::dup2(w, kept) } != kept {
                    return false;
                }
                let outside = dup_at_least(w, keep_end + 1);
                if sweep_inherited(keep_end, SweepMode::HardClose, 1024).is_err() {
                    return false;
                }
                fd_flags(kept) >= 0 && fd_flags(outside) == -1
            }),
            "the keep window must survive a hard-close sweep"
        );
    }
}
