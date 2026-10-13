//! Landlock filesystem restrictions.
//!
//! Uses the `landlock` crate (by the kernel subsystem maintainer) to apply
//! filesystem access restrictions. Supports ABI v1-v6 with best-effort
//! compatibility — unsupported access rights on older kernels are silently
//! ignored, while core restrictions are always enforced.

use std::path::Path;

use landlock::{
    ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, Scope, make_bitflags, path_beneath_rules,
};

use crate::{Error, Profile};

/// Apply Landlock filesystem restrictions to the current process.
///
/// `target_binary` is the resolved path to the command that will be
/// `execve`-d after Landlock is applied. When `allow_exec` is false,
/// Execute is stripped from all paths except the target binary and
/// the ELF interpreter (needed for the wrapper's own execve and
/// dynamic linking).
///
/// # Errors
///
/// Returns an error if Landlock is unavailable (pre-5.13 kernel) or
/// if all path rules fail to apply. Individual path failures are logged
/// but do not abort — only a complete failure is fatal.
///
/// # Security
///
/// - Calls `prctl(PR_SET_NO_NEW_PRIVS)` via the crate's `set_no_new_privs(true)`.
/// - Uses `CompatLevel::BestEffort` so the strictest possible restrictions
///   are applied for the running kernel's ABI version.
/// - Fail-closed: returns error if the ruleset is `NotEnforced`.
///   When both path lists are empty, applies a deny-all filesystem
///   policy (ruleset with zero rules) rather than skipping Landlock.
///
/// # Limitations
///
/// `dlopen()` from write paths is NOT blocked — Landlock Execute
/// controls `execve` path resolution, not `mmap(PROT_EXEC)`.
///
/// The ELF interpreter grant creates a bypass: `ld.so /bin/sh` works
/// because ld.so has Execute and loads targets via mmap. Robust exec
/// blocking against command injection requires seccomp `execve`
/// interception (future work).
#[must_use = "landlock errors must be handled — the process may be unsandboxed"]
pub fn apply(profile: &Profile, target_binary: Option<&Path>) -> crate::Result<()> {
    let read_paths = &profile.read_paths;
    let write_paths = &profile.write_paths;

    if read_paths.is_empty() && write_paths.is_empty() {
        log::warn!("landlock: no paths configured, applying deny-all filesystem policy");
    }

    // Use the highest ABI we fully support. The crate handles
    // best-effort downgrade for access rights added in later ABIs.
    let abi = ABI::V5;

    let read_access = if profile.allow_exec {
        make_bitflags!(AccessFs::{ Execute | ReadFile | ReadDir })
    } else {
        make_bitflags!(AccessFs::{ ReadFile | ReadDir })
    };

    let write_access = if profile.allow_exec {
        AccessFs::from_all(abi)
    } else {
        AccessFs::from_all(abi) & !make_bitflags!(AccessFs::{ Execute })
    };

    let mut builder = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| Error::Landlock(format!("handle access: {e}")))?;
    if profile.deny_unix_sockets {
        builder = builder
            .scope(Scope::AbstractUnixSocket)
            .map_err(|e| Error::Landlock(format!("scope AbstractUnixSocket: {e}")))?;
    }
    let mut ruleset = builder
        .create()
        .map_err(|e| Error::Landlock(format!("create ruleset: {e}")))?;

    // Add read-only path rules.
    let read_rules = path_beneath_rules(read_paths, read_access);
    ruleset = ruleset
        .add_rules(read_rules)
        .map_err(|e| Error::Landlock(format!("add read rules: {e}")))?;

    // Add read-write path rules.
    let write_rules = path_beneath_rules(write_paths, write_access);
    ruleset = ruleset
        .add_rules(write_rules)
        .map_err(|e| Error::Landlock(format!("add write rules: {e}")))?;

    // When allow_exec is false, grant Execute only on the target
    // binary and the ELF interpreter so the wrapper's execve and
    // dynamic linking work.
    if !profile.allow_exec {
        let exec_read = make_bitflags!(AccessFs::{ Execute | ReadFile });
        if let Some(binary) = target_binary {
            if let Ok(fd) = PathFd::new(binary) {
                let rule = PathBeneath::new(fd, exec_read);
                ruleset = ruleset
                    .add_rule(rule)
                    .map_err(|e| Error::Landlock(format!("add exec rule (binary): {e}")))?;
            }
        }
        if let Some(interp) = resolve_elf_interpreter(target_binary) {
            if let Ok(fd) = PathFd::new(&interp) {
                let rule = PathBeneath::new(fd, exec_read);
                ruleset = ruleset
                    .add_rule(rule)
                    .map_err(|e| Error::Landlock(format!("add exec rule (ld.so): {e}")))?;
            }
        }
    }

    // Enforce. set_no_new_privs(true) is the default and calls
    // prctl(PR_SET_NO_NEW_PRIVS) internally.
    let status = ruleset
        .restrict_self()
        .map_err(|e| Error::Landlock(format!("restrict self: {e}")))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            log::info!("landlock: applied (FullyEnforced, ABI {:?})", abi_version());
            Ok(())
        }
        RulesetStatus::PartiallyEnforced => {
            let abi = abi_version();
            let mut missing = Vec::new();
            if abi <= 1 {
                missing.push("Refer");
            }
            if abi <= 2 {
                missing.push("Truncate");
            }
            if abi <= 3 {
                missing.push("IOCTL_DEV");
            }
            if profile.deny_unix_sockets && abi <= 5 {
                missing.push("SCOPE_ABSTRACT_UNIX");
            }
            log::info!("landlock: applied (PartiallyEnforced, ABI {abi})");
            if !missing.is_empty() {
                log::warn!("landlock: ABI {abi} — not enforced: {}", missing.join(", "));
            }
            Ok(())
        }
        RulesetStatus::NotEnforced => Err(Error::Landlock("ruleset not enforced".into())),
    }
}

/// Resolve the ELF interpreter path from the target binary's PT_INTERP
/// program header. Falls back to well-known paths if reading fails.
fn resolve_elf_interpreter(target: Option<&Path>) -> Option<std::path::PathBuf> {
    if let Some(binary) = target {
        if let Ok(mut file) = std::fs::File::open(binary) {
            use std::io::Read;
            let mut buf = vec![0u8; 4096];
            let n = file.read(&mut buf).unwrap_or(0);
            buf.truncate(n);
            if let Some(interp) = parse_pt_interp(&buf) {
                let p = std::path::PathBuf::from(interp);
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }

    // Fallback to well-known paths.
    #[cfg(target_arch = "x86_64")]
    let fallback = "/lib64/ld-linux-x86-64.so.2";
    #[cfg(target_arch = "aarch64")]
    let fallback = "/lib/ld-linux-aarch64.so.1";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let fallback = "";

    let p = std::path::PathBuf::from(fallback);
    if p.exists() { Some(p) } else { None }
}

/// Parse PT_INTERP from an ELF binary's program headers.
fn parse_pt_interp(data: &[u8]) -> Option<String> {
    // ELF magic: 0x7f 'E' 'L' 'F'
    if data.len() < 64 || data[..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }

    let class = data[4]; // 1 = 32-bit, 2 = 64-bit
    if class != 2 {
        return None; // only 64-bit
    }
    if data[5] != 1 {
        return None; // only little-endian
    }

    // e_phoff (offset 32, 8 bytes), e_phentsize (offset 54, 2 bytes),
    // e_phnum (offset 56, 2 bytes).
    let e_phoff = u64::from_le_bytes(data[32..40].try_into().ok()?) as usize;
    let e_phentsize = u16::from_le_bytes(data[54..56].try_into().ok()?) as usize;
    let e_phnum = u16::from_le_bytes(data[56..58].try_into().ok()?) as usize;

    // PT_INTERP = 3
    for i in 0..e_phnum {
        let off = e_phoff.checked_add(i.checked_mul(e_phentsize)?)?;
        if off.checked_add(e_phentsize)? > data.len() {
            return None;
        }
        let p_type = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
        if p_type == 3 {
            // p_offset at offset 8 (8 bytes), p_filesz at offset 32 (8 bytes)
            let p_offset = u64::from_le_bytes(data[off + 8..off + 16].try_into().ok()?) as usize;
            let p_filesz = u64::from_le_bytes(data[off + 32..off + 40].try_into().ok()?) as usize;
            let end = p_offset.checked_add(p_filesz)?;
            if end > data.len() {
                return None;
            }
            let segment = &data[p_offset..end];
            // NUL-terminated string.
            let end = segment
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(segment.len());
            return String::from_utf8(segment[..end].to_vec()).ok();
        }
    }
    None
}

/// Probe the Landlock ABI version supported by the running kernel.
///
/// Returns 0 if Landlock is unavailable (pre-5.13 kernel, or disabled
/// via kernel config / boot parameter).
///
/// Uses the `landlock_create_ruleset` syscall with
/// `LANDLOCK_CREATE_RULESET_ATTR_SIZE_VER` flag, which returns the ABI
/// version without creating a ruleset or modifying process state.
pub fn abi_version() -> u32 {
    // SAFETY: landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_ATTR_SIZE_VER)
    // is a read-only probe — it does not modify process state. Returns the
    // ABI version on success or -1 with errno on failure.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            1u32, // LANDLOCK_CREATE_RULESET_ATTR_SIZE_VER
        )
    };

    if ret < 0 { 0 } else { ret as u32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_paths_is_noop() {
        let profile = Profile::default();
        assert!(apply(&profile, None).is_ok());
    }

    #[test]
    fn abi_version_probe() {
        // On a modern kernel, this should return >= 1.
        // On CI without Landlock, it returns 0. Both are valid.
        let v = abi_version();
        eprintln!("landlock ABI version: {v}");
        // Just assert it doesn't panic.
    }
}
