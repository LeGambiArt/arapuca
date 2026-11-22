//! Arapuca — Linux process sandbox.
//!
//! Provides Landlock filesystem restrictions, seccomp BPF syscall filtering,
//! cgroups v2 resource limits, network namespace isolation, and process
//! lifecycle management. Available as both a Rust library (with C FFI) and
//! a CLI binary.
//!
//! The sandbox is a mandatory security boundary — even a fully compromised
//! subprocess is contained by OS-enforced restrictions.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod audit;
#[cfg(target_os = "linux")]
pub mod bridge;
#[cfg(target_os = "linux")]
pub mod cgroup;
pub mod diskquota;
pub mod dns;
pub mod env;
mod error;
pub mod ffi;
pub mod images;
#[cfg(target_os = "linux")]
pub mod landlock;
#[cfg(target_os = "linux")]
pub mod netns;
#[cfg(target_os = "linux")]
pub mod pidns;
pub mod platform;
mod process;
mod profile;
#[cfg(unix)]
pub mod rlimit;
#[cfg(seccomp_supported)]
pub mod seccomp;
pub mod selfexec;
#[cfg(unix)]
pub mod terminal;
#[cfg(seccomp_supported)]
pub mod unotify;
mod validate;
#[cfg(target_os = "linux")]
pub mod vm;
pub mod wrapper;

pub use process::Process;

pub use audit::sanitize_audit_string;
pub use error::Error;
pub use profile::{
    CgroupPolicy, Config, GuestFile, ImageSource, Isolation, MicroVmConfig, Profile, ResourceUsage,
    SeccompProfile, UnixSocketConnectPolicy,
};
#[cfg(unix)]
pub use validate::{
    GUEST_PATH_DENY_PREFIXES, normalize_path, reject_cgroup_paths, validate_guest_file_content,
    validate_guest_path, validate_guest_permissions, validate_work_dir,
};
pub use validate::{MAX_GUEST_FILE_SIZE, MAX_GUEST_WRITE_FILES, sanitize_task_id};

/// Result type for arapuca operations.
pub type Result<T> = std::result::Result<T, Error>;
