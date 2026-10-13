//! Windows sandbox implementation.
//!
//! Provides process isolation via Job Objects (resource limits, UI
//! restrictions, kill-on-close), process creation via `CreateProcessW`
//! with `PROC_THREAD_ATTRIBUTE_JOB_LIST` for atomic Job assignment,
//! and environment hardening.
//!
//! Current limitations (documented as known gaps):
//! - No desktop/window station isolation
//! - No file size limits (no Windows per-process equivalent)

#[cfg(not(target_pointer_width = "64"))]
compile_error!("arapuca requires 64-bit Windows");

use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, LocalFree, TRUE,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW,
    SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES, WinCapabilityInternetClientSid,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicUIRestrictions,
    JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, InitializeProcThreadAttributeList,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
};

use crate::platform::Sandbox;
use crate::{Config, Error, process::Process};

const PROC_THREAD_ATTRIBUTE_JOB_LIST: usize = 0x0002_000D;
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: usize = 0x0002_0007;
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
const PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: usize = 0x0002_000F;

// PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: opt the child out
// of the implicit "ALL APPLICATION PACKAGES" SID so it runs as a Less
// Privileged AppContainer (LPAC). Without this, every AppContainer
// process retains broad read/execute access to System32, Program
// Files, and other locations the "ALL APPLICATION PACKAGES" group is
// granted, defeating much of the intended confinement.
const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 0x1;

// QWORD 1 of PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY.
// ACG (1 << 36, prohibit dynamic code) is deliberately omitted: it
// breaks JIT runtimes (Python, Node, Java, .NET). Add as opt-in via
// a Profile flag if needed for compiled-binary-only workloads.
const MITIGATION_POLICY: u64 = 0x01           // DEP enable
    | 0x02                                     // DEP ATL thunk enable
    | (1 << 8)                                 // mandatory ASLR
    | (1 << 12)                                // heap terminate on corruption
    | (1 << 16)                                // bottom-up ASLR
    | (1 << 20)                                // high-entropy ASLR (x64)
    | (1 << 24)                                // strict handle checks
    | (1 << 28)                                // Win32k syscall disable
    | (1 << 32)                                // extension point disable
    | (1 << 52)                                // image load no remote
    | (1 << 56); // image load no low label

/// Windows sandbox implementation.
pub struct Windows;

impl Windows {
    pub fn new() -> crate::Result<Self> {
        Ok(Windows)
    }
}

impl Sandbox for Windows {
    fn launch(&self, cfg: &Config, cmd: &str, args: &[&str]) -> crate::Result<Process> {
        cfg.profile.validate_unix_socket_policy()?;
        crate::sanitize_task_id(&cfg.task_id)?;

        let tmp_dir = crate::env::make_tmp_dir(&cfg.task_id)?;
        let cleanup_tmp = |_: &Error| {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        };

        let job_handle = create_job_object(&cfg.profile).inspect_err(cleanup_tmp)?;

        let env_vars = build_env(cfg, &tmp_dir);
        let env_block = encode_env_block(&env_vars);
        let mut cmdline = quote_args(cmd, args);

        let work_dir: Option<Vec<u16>> = cfg.work_dir.as_ref().map(|p| encode_work_dir(p));

        let stdio_handles = duplicate_stdio().inspect_err(cleanup_tmp)?;
        let mut handle_list: Vec<HANDLE> = stdio_handles
            .iter()
            .map(|h| h.as_raw_handle() as HANDLE)
            .collect();
        let inherit_handles = if handle_list.is_empty() { 0 } else { TRUE };

        // ── AppContainer path: filesystem + network isolation ──
        //
        // AppContainer confinement is always engaged, even with zero
        // explicitly granted paths: it denies filesystem access by
        // default, which is the load-bearing property. An earlier
        // version of this code only engaged it when read_paths or
        // write_paths was non-empty, so the common zero-path case
        // silently fell through to a restricted-token-only fallback
        // that provided NO filesystem read confinement at all. That
        // fallback path has been removed (see git history) along with
        // this always-true condition, so a future change can't
        // silently reintroduce the same gap.
        let container_name_owned: String;
        let mut saved_dacls: Vec<SavedDacl> = Vec::new();
        let app_container_sid: AppContainerSid;
        let mut net_sid_buf = vec![0u8; 68]; // MAX_SID_SIZE
        let mut capabilities: Vec<SID_AND_ATTRIBUTES> = Vec::new();
        let mut sec_caps: SECURITY_CAPABILITIES = unsafe { std::mem::zeroed() };

        {
            let name = container_name(&cfg.task_id);
            let ac_sid = create_app_container(&name).inspect_err(cleanup_tmp)?;

            // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
            const READ_EXEC: u32 = 0x120089 | 0x1200A0;
            // FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE
            const READ_WRITE_EXEC: u32 = 0x120089 | 0x120116 | 0x1200A0 | 0x10000;

            // Closure to rollback DACLs + delete container on error.
            let rollback = |dacls: &[SavedDacl], cname: &str| {
                for sd in dacls {
                    if let Err(e) = restore_dacl(sd) {
                        log::warn!("rollback DACL restore: {e}");
                    }
                }
                if let Err(e) = delete_app_container(cname) {
                    log::warn!("rollback AppContainer delete: {e}");
                }
                let _ = std::fs::remove_dir_all(&tmp_dir);
            };

            // Grant read access to read_paths.
            for path in &cfg.profile.read_paths {
                match save_dacl(path) {
                    Ok(sd) => {
                        if let Err(e) = grant_path_access(path, ac_sid.sid, READ_EXEC, true) {
                            rollback(&saved_dacls, &name);
                            return Err(e);
                        }
                        saved_dacls.push(sd);
                    }
                    Err(e) => {
                        rollback(&saved_dacls, &name);
                        return Err(e);
                    }
                }
            }

            // Grant write access to write_paths + tmp_dir.
            let write_with_tmp: Vec<PathBuf> = cfg
                .profile
                .write_paths
                .iter()
                .cloned()
                .chain(std::iter::once(tmp_dir.clone()))
                .collect();

            for path in &write_with_tmp {
                match save_dacl(path) {
                    Ok(sd) => {
                        if let Err(e) = grant_path_access(path, ac_sid.sid, READ_WRITE_EXEC, true) {
                            rollback(&saved_dacls, &name);
                            return Err(e);
                        }
                        saved_dacls.push(sd);
                    }
                    Err(e) => {
                        rollback(&saved_dacls, &name);
                        return Err(e);
                    }
                }
            }

            // Network capability: grant internetClient unless isolated.
            if !cfg.profile.use_netns {
                let mut sid_size: u32 = net_sid_buf.len() as u32;
                // SAFETY: net_sid_buf is large enough for any SID.
                let ret = unsafe {
                    CreateWellKnownSid(
                        WinCapabilityInternetClientSid,
                        std::ptr::null_mut(),
                        net_sid_buf.as_mut_ptr().cast(),
                        &mut sid_size,
                    )
                };
                if ret != 0 {
                    capabilities.push(SID_AND_ATTRIBUTES {
                        Sid: net_sid_buf.as_mut_ptr().cast(),
                        Attributes: 0x4, // SE_GROUP_ENABLED
                    });
                } else {
                    log::warn!(
                        "CreateWellKnownSid(internetClient) failed, child will have no network"
                    );
                }
            }

            sec_caps.AppContainerSid = ac_sid.sid;
            if !capabilities.is_empty() {
                sec_caps.Capabilities = capabilities.as_mut_ptr();
                sec_caps.CapabilityCount = capabilities.len() as u32;
            }

            container_name_owned = name;
            app_container_sid = ac_sid;
        }

        // ── Build attribute list ──
        // LPAC is opt-in (cfg.profile.lpac): AppContainer alone already
        // denies filesystem access by default; LPAC additionally strips
        // the "ALL APPLICATION PACKAGES" SID, which most non-Microsoft-
        // signed binaries depend on for registry/DLL access.
        let use_lpac = cfg.profile.lpac;
        let attr_count = if use_lpac { 5 } else { 4 };
        let mut lpac_policy: u32 = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        let job_raw = job_handle.as_raw_handle() as HANDLE;
        let policy_qword2 = if !cfg.profile.allow_exec {
            1u64 << 44 // PROCESS_CREATION_CHILD_PROCESS_RESTRICTED (ALWAYS_ON)
        } else {
            0
        };
        let mut policy = [MITIGATION_POLICY, policy_qword2];

        // After DACLs are granted, error cleanup must also restore
        // them and delete the AppContainer profile.
        let cleanup_full = |_: &Error| {
            rollback_appcontainer(&saved_dacls, &container_name_owned, &tmp_dir);
        };

        let mut attr_list = AttributeList::new(attr_count).inspect_err(cleanup_full)?;
        attr_list.add_job_list(&job_raw).inspect_err(cleanup_full)?;
        attr_list
            .add_handle_list(&mut handle_list)
            .inspect_err(cleanup_full)?;
        attr_list
            .add_mitigation_policy(&mut policy)
            .inspect_err(cleanup_full)?;

        attr_list
            .add_security_capabilities(&mut sec_caps)
            .inspect_err(cleanup_full)?;
        if use_lpac {
            attr_list
                .add_all_app_packages_policy(&mut lpac_policy)
                .inspect_err(cleanup_full)?;
        }

        // ── Build STARTUPINFOEXW ──
        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        if handle_list.len() >= 3 {
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = handle_list[0];
            si.StartupInfo.hStdOutput = handle_list[1];
            si.StartupInfo.hStdError = handle_list[2];
        }
        si.lpAttributeList = attr_list.as_ptr();

        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // SECURITY_CAPABILITIES creates the lowbox token at spawn. No
        // CREATE_SUSPENDED or token swap — swapping the token would
        // destroy AppContainer isolation. Privilege stripping is not
        // applied; AppContainer's deny-by-default access model renders
        // most privileges inert.
        let ret = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                inherit_handles,
                CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                env_block.as_ptr().cast(),
                work_dir.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
                &raw mut si.StartupInfo,
                &mut pi,
            )
        };
        drop(attr_list);
        if ret == 0 {
            let err = std::io::Error::last_os_error();
            rollback_appcontainer(&saved_dacls, &container_name_owned, &tmp_dir);
            return Err(Error::Process(format!("CreateProcessW: {err}")));
        }

        unsafe { CloseHandle(pi.hThread) };
        let process_handle = unsafe { OwnedHandle::from_raw_handle(pi.hProcess) };

        // The kernel copied the SID during CreateProcessW, so the
        // AppContainerSid can be freed now.
        drop(app_container_sid);

        Ok(Process {
            process_handle,
            process_id: pi.dwProcessId,
            tmp_dir,
            waited: false,
            job_handle: Some(job_handle),
            container_name: Some(container_name_owned),
            saved_dacls,
            audit_ctx: None,
            final_stats: None,
        })
    }

    fn available(&self) -> crate::Result<()> {
        Ok(())
    }

    fn netns_available(&self) -> bool {
        false
    }

    fn cgroups_available(&self) -> bool {
        false
    }
}

// ─── Stdio handle duplication ──────────────────────────────────────

fn duplicate_stdio() -> crate::Result<Vec<OwnedHandle>> {
    let std_handles = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
    let mut result = Vec::with_capacity(3);

    for &id in &std_handles {
        let h = unsafe { GetStdHandle(id) };
        if h == INVALID_HANDLE_VALUE || h == 0 as HANDLE {
            continue;
        }
        let dup = duplicate_as_inheritable(h)?;
        result.push(dup);
    }
    Ok(result)
}

fn duplicate_as_inheritable(handle: HANDLE) -> crate::Result<OwnedHandle> {
    let current = unsafe { GetCurrentProcess() };
    let mut dup: HANDLE = std::ptr::null_mut();
    // SAFETY: current process and handle are valid. The duplicated
    // handle is inheritable (bInheritHandle=TRUE) with same access.
    let ret = unsafe {
        DuplicateHandle(
            current,
            handle,
            current,
            &mut dup,
            0,
            TRUE,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "DuplicateHandle: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: dup is a valid handle from successful DuplicateHandle.
    Ok(unsafe { OwnedHandle::from_raw_handle(dup) })
}

// ─── Attribute list RAII wrapper ───────────────────────────────────

struct AttributeList {
    buffer: Vec<u8>,
}

impl AttributeList {
    fn new(count: u32) -> crate::Result<Self> {
        let mut size: usize = 0;
        // SAFETY: First call with null determines required buffer size.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut size);
        }
        if size == 0 {
            return Err(Error::Process(
                "InitializeProcThreadAttributeList: size is 0".into(),
            ));
        }
        let mut buffer = vec![0u8; size];
        // SAFETY: buffer is large enough (size returned by first call).
        let ret = unsafe {
            InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), count, 0, &mut size)
        };
        if ret == 0 {
            return Err(Error::Process(format!(
                "InitializeProcThreadAttributeList: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self { buffer })
    }

    fn as_ptr(&mut self) -> *mut std::ffi::c_void {
        self.buffer.as_mut_ptr().cast()
    }

    fn add_job_list(&mut self, job: &HANDLE) -> crate::Result<()> {
        // SAFETY: self.buffer is a valid initialized attribute list.
        // job points to a valid HANDLE that outlives the attribute list.
        let ret = unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST,
                (job as *const HANDLE).cast(),
                std::mem::size_of::<HANDLE>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(Error::Process(format!(
                "UpdateProcThreadAttribute(JOB_LIST): {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn add_handle_list(&mut self, handles: &mut [HANDLE]) -> crate::Result<()> {
        if handles.is_empty() {
            return Ok(());
        }
        // SAFETY: handles is a valid array that outlives the attribute list.
        let ret = unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles.as_mut_ptr().cast(),
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(Error::Process(format!(
                "UpdateProcThreadAttribute(HANDLE_LIST): {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn add_mitigation_policy(&mut self, policy: &mut [u64; 2]) -> crate::Result<()> {
        // SAFETY: policy is a valid [u64; 2] that outlives the attribute list.
        let ret = unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                policy.as_mut_ptr().cast(),
                std::mem::size_of::<[u64; 2]>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(Error::Process(format!(
                "UpdateProcThreadAttribute(MITIGATION_POLICY): {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn add_security_capabilities(&mut self, caps: &mut SECURITY_CAPABILITIES) -> crate::Result<()> {
        // SAFETY: caps is a valid SECURITY_CAPABILITIES that outlives
        // the attribute list.
        let ret = unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                (caps as *mut SECURITY_CAPABILITIES).cast(),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(Error::Process(format!(
                "UpdateProcThreadAttribute(SECURITY_CAPABILITIES): {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Opt the child out of "ALL APPLICATION PACKAGES" (LPAC).
    fn add_all_app_packages_policy(&mut self, policy: &mut u32) -> crate::Result<()> {
        // SAFETY: policy is a valid u32 that outlives the attribute list.
        let ret = unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                (policy as *mut u32).cast(),
                std::mem::size_of::<u32>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(Error::Process(format!(
                "UpdateProcThreadAttribute(ALL_APPLICATION_PACKAGES_POLICY): {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: buffer was successfully initialized.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

// ─── Job Object ────────────────────────────────────────────────────

fn create_job_object(profile: &crate::Profile) -> crate::Result<OwnedHandle> {
    // SAFETY: CreateJobObjectW with NULL security attributes and name
    // creates an anonymous Job Object.
    let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if raw == INVALID_HANDLE_VALUE || raw == 0 as HANDLE {
        return Err(Error::Process(format!(
            "CreateJobObjectW: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: raw is a valid handle we own (verified above).
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };

    // SAFETY: handle is a valid Job Object handle.
    let ret = unsafe {
        windows_sys::Win32::Foundation::SetHandleInformation(
            handle.as_raw_handle() as HANDLE,
            HANDLE_FLAG_INHERIT,
            0,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "SetHandleInformation(non-inheritable): {}",
            std::io::Error::last_os_error()
        )));
    }

    set_job_limits(&handle, profile)?;
    set_job_ui_restrictions(&handle)?;

    Ok(handle)
}

fn set_job_limits(handle: &OwnedHandle, profile: &crate::Profile) -> crate::Result<()> {
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };

    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    if profile.max_memory_mb > 0 {
        info.JobMemoryLimit = (profile.max_memory_mb * 1024 * 1024) as usize;
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
    }

    if profile.max_pids > 0 {
        info.BasicLimitInformation.ActiveProcessLimit = profile.max_pids;
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    }

    // SAFETY: handle is a valid Job Object, info is a valid struct.
    let ret = unsafe {
        SetInformationJobObject(
            handle.as_raw_handle() as HANDLE,
            JobObjectExtendedLimitInformation,
            (&raw const info).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "SetInformationJobObject(ExtendedLimit): {}",
            std::io::Error::last_os_error()
        )));
    }

    if profile.max_cpu_pct > 0 {
        set_job_cpu_limit(handle, profile.max_cpu_pct)?;
    }

    Ok(())
}

fn set_job_cpu_limit(handle: &OwnedHandle, cpu_pct: u32) -> crate::Result<()> {
    let mut info: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
    info.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    // CpuRate is in hundredths of a percent of total system CPU (1-10000).
    // Linux cgroups use per-core percentage (200 = 2 cores), so we divide
    // by core count to translate. Falls back to 1 core if unavailable,
    // which errs on the side of more restrictive.
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(1);
    let rate = (u64::from(cpu_pct) * 100 / num_cpus).clamp(1, 10000) as u32;
    info.Anonymous.CpuRate = rate;

    // SAFETY: handle is a valid Job Object, info is a valid struct.
    let ret = unsafe {
        SetInformationJobObject(
            handle.as_raw_handle() as HANDLE,
            JobObjectCpuRateControlInformation,
            (&raw const info).cast(),
            std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "SetInformationJobObject(CpuRate): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn set_job_ui_restrictions(handle: &OwnedHandle) -> crate::Result<()> {
    let info = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_EXITWINDOWS,
    };

    // SAFETY: handle is a valid Job Object, info is a valid struct.
    let ret = unsafe {
        SetInformationJobObject(
            handle.as_raw_handle() as HANDLE,
            JobObjectBasicUIRestrictions,
            (&raw const info).cast(),
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "SetInformationJobObject(UIRestrictions): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

// ─── Environment ───────────────────────────────────────────────────

fn rollback_appcontainer(saved_dacls: &[SavedDacl], container_name: &str, tmp_dir: &Path) {
    for sd in saved_dacls {
        if let Err(e) = restore_dacl(sd) {
            log::warn!("rollback DACL restore: {e}");
        }
    }
    if let Err(e) = delete_app_container(container_name) {
        log::warn!("rollback AppContainer delete: {e}");
    }
    let _ = std::fs::remove_dir_all(tmp_dir);
}

fn build_env(cfg: &Config, tmp_dir: &Path) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = crate::env::filter_caller_env(&cfg.env).passed;
    const OVERRIDDEN: &[&str] = &[
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "HOMEDRIVE",
        "HOMEPATH",
        "USERNAME",
        "TEMP",
        "TMP",
        "PATH",
        "SystemRoot",
        "LANG",
    ];
    env.retain(|(key, _)| {
        !OVERRIDDEN
            .iter()
            .any(|managed| key.eq_ignore_ascii_case(managed))
    });

    if let Some(ref proxy) = cfg.network_proxy_socket {
        env.push((
            "AGENT_NETWORK_PROXY".into(),
            proxy.to_string_lossy().into_owned(),
        ));
    }

    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let profile = tmp_dir.to_string_lossy().into_owned();
    let (home_drive, home_path) = split_windows_home(&profile);

    env.push(("USERPROFILE".into(), profile.clone()));
    env.push(("APPDATA".into(), profile.clone()));
    env.push(("LOCALAPPDATA".into(), profile));
    env.push(("HOMEDRIVE".into(), home_drive));
    env.push(("HOMEPATH".into(), home_path));
    env.push(("USERNAME".into(), "sandbox".into()));
    env.push(("TEMP".into(), tmp_dir.to_string_lossy().into_owned()));
    env.push(("TMP".into(), tmp_dir.to_string_lossy().into_owned()));
    env.push((
        "PATH".into(),
        format!(r"{system_root}\system32;{system_root}"),
    ));
    env.push(("SystemRoot".into(), system_root));
    env.push(("LANG".into(), "C.UTF-8".into()));

    env
}

/// Split a Windows absolute path into `HOMEDRIVE` / `HOMEPATH` form.
///
/// Falls back to `C:` + the full path when no drive letter is present
/// (for example a Volume GUID path used only in tests).
fn split_windows_home(path: &str) -> (String, String) {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let drive = path[..2].to_ascii_uppercase();
        let rest = &path[2..];
        let home_path = if rest.is_empty() {
            r"\".to_string()
        } else {
            rest.to_string()
        };
        return (drive, home_path);
    }
    ("C:".into(), path.to_string())
}

// ─── Utilities ─────────────────────────────────────────────────────

/// Build a Windows command line from a command and arguments.
///
/// Implements `CommandLineToArgvW`-compatible quoting (MSVC C runtime
/// rules). Arguments containing spaces, tabs, or quotes are wrapped
/// in double quotes with proper backslash escaping.
///
/// Returns a null-terminated mutable UTF-16 buffer — `CreateProcessW`
/// may modify `lpCommandLine` in-place.
pub(crate) fn quote_args(cmd: &str, args: &[&str]) -> Vec<u16> {
    use std::ffi::OsStr;

    let mut cmdline = String::new();
    quote_arg(cmd, &mut cmdline);
    for arg in args {
        cmdline.push(' ');
        quote_arg(arg, &mut cmdline);
    }
    OsStr::new(&cmdline)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Encode a working directory for `CreateProcessW`.
///
/// `Path::canonicalize` returns verbatim (`\\?\`) paths on Windows. Console
/// programs such as `cmd.exe` interpret a verbatim drive path as a UNC path
/// and silently fall back to the Windows directory. Convert the verbatim
/// prefix back to its regular Win32 form before spawning the child.
fn encode_work_dir(path: &Path) -> Vec<u16> {
    use std::ffi::OsStr;

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    let verbatim = OsStr::new(r"\\?\").encode_wide().collect::<Vec<_>>();
    let verbatim_unc = OsStr::new(r"\\?\UNC\").encode_wide().collect::<Vec<_>>();
    if wide.starts_with(&verbatim_unc) {
        wide.drain(..verbatim_unc.len());
        wide.splice(0..0, OsStr::new(r"\\").encode_wide());
    } else if wide.starts_with(&verbatim)
        && wide.len() > verbatim.len() + 2
        && (wide[verbatim.len()] >= b'A' as u16 && wide[verbatim.len()] <= b'Z' as u16
            || wide[verbatim.len()] >= b'a' as u16 && wide[verbatim.len()] <= b'z' as u16)
        && wide[verbatim.len() + 1] == b':' as u16
    {
        wide.drain(..verbatim.len());
    }
    wide.push(0);
    wide
}

fn quote_arg(arg: &str, out: &mut String) {
    if arg.is_empty() {
        out.push_str("\"\"");
        return;
    }
    let needs_quoting = arg.bytes().any(|b| b == b' ' || b == b'\t' || b == b'"');
    if !needs_quoting {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes: usize = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push('\\');
                out.push('"');
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // Trailing backslashes must be doubled — they would otherwise
    // escape the closing quote.
    for _ in 0..backslashes * 2 {
        out.push('\\');
    }
    out.push('"');
}

/// Encode environment variables into a Windows environment block.
///
/// The block is UTF-16 encoded, sorted by key (case-insensitive),
/// with each entry as `KEY=VALUE\0` and terminated by an extra `\0`.
/// Required for `CreateProcessW` with `CREATE_UNICODE_ENVIRONMENT`.
pub(crate) fn encode_env_block(vars: &[(String, String)]) -> Vec<u16> {
    use std::ffi::OsStr;

    let mut sorted: Vec<&(String, String)> = vars.iter().collect();
    sorted.sort_by_key(|a| a.0.to_ascii_uppercase());

    let mut block = Vec::new();
    for (k, v) in &sorted {
        let entry = format!("{k}={v}");
        block.extend(OsStr::new(&entry).encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

// ─── DACL save/restore ─────────────────────────────────────────────

const DACL_SECURITY_INFORMATION: u32 = 4;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

/// Saved DACL state for a path — used to restore the original
/// security descriptor after the sandbox exits.
pub struct SavedDacl {
    path: PathBuf,
    sd: *mut std::ffi::c_void,
}

// SAFETY: SavedDacl holds a system-allocated security descriptor
// pointer accessed only for restoration (single-threaded). Not Sync
// because concurrent reads of the raw pointer would be unsafe.
unsafe impl Send for SavedDacl {}

impl Drop for SavedDacl {
    fn drop(&mut self) {
        if !self.sd.is_null() {
            // SAFETY: sd was allocated by GetNamedSecurityInfoW.
            unsafe { LocalFree(self.sd) };
        }
    }
}

/// Save the current DACL of a path for later restoration.
pub fn save_dacl(path: &Path) -> crate::Result<SavedDacl> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();

    // SAFETY: wide_path is null-terminated. sd is a valid out pointer.
    // GetNamedSecurityInfoW allocates the security descriptor; caller
    // must free with LocalFree.
    let err = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return Err(Error::Process(format!(
            "GetNamedSecurityInfoW({}): error {err}",
            path.display()
        )));
    }

    Ok(SavedDacl {
        path: path.to_path_buf(),
        sd,
    })
}

/// Restore a previously saved DACL to its path.
pub fn restore_dacl(saved: &SavedDacl) -> crate::Result<()> {
    if saved.sd.is_null() {
        return Ok(());
    }

    let wide_path: Vec<u16> = saved
        .path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Extract the DACL from the saved security descriptor.
    let mut dacl: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut dacl_present: i32 = 0;
    let mut dacl_defaulted: i32 = 0;

    // SAFETY: saved.sd is a valid security descriptor from
    // GetNamedSecurityInfoW.
    let ret = unsafe {
        windows_sys::Win32::Security::GetSecurityDescriptorDacl(
            saved.sd,
            &mut dacl_present,
            &mut dacl as *mut *mut _ as *mut *mut _,
            &mut dacl_defaulted,
        )
    };
    if ret == 0 {
        return Err(Error::Process(format!(
            "GetSecurityDescriptorDacl({}): {}",
            saved.path.display(),
            std::io::Error::last_os_error()
        )));
    }

    let dacl_ptr = if dacl_present != 0 {
        dacl as *const _
    } else {
        std::ptr::null()
    };

    // SAFETY: wide_path is null-terminated, dacl_ptr is valid or null.
    let err = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr() as *mut _,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl_ptr,
            std::ptr::null(),
        )
    };
    if err != 0 {
        return Err(Error::Process(format!(
            "SetNamedSecurityInfoW restore({}): error {err}",
            saved.path.display()
        )));
    }

    Ok(())
}

/// Grant an AppContainer SID access to a path by adding an ACE.
///
/// # Safety requirements on `sid`
/// - Must be a valid, non-null pointer to a Windows SID structure
/// - Must remain valid for the duration of this call
pub fn grant_path_access(
    path: &Path,
    sid: *mut std::ffi::c_void,
    access_mask: u32,
    inherit: bool,
) -> crate::Result<()> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let inherit_flags: u32 = if inherit {
        1 | 2 // CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        0
    };

    let mut ea: EXPLICIT_ACCESS_W = unsafe { std::mem::zeroed() };
    ea.grfAccessPermissions = access_mask;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = inherit_flags;
    ea.Trustee = unsafe { std::mem::zeroed::<TRUSTEE_W>() };
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = 0; // TRUSTEE_IS_UNKNOWN — AppContainer SIDs are dynamic
    ea.Trustee.ptstrName = sid as *mut u16;

    // Get existing DACL.
    let mut existing_dacl: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();

    let err = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut existing_dacl as *mut *mut _ as *mut *mut _,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return Err(Error::Process(format!(
            "GetNamedSecurityInfoW({}): error {err}",
            path.display()
        )));
    }

    // Merge new ACE with existing DACL.
    let mut new_dacl: *mut std::ffi::c_void = std::ptr::null_mut();
    let err = unsafe {
        SetEntriesInAclW(
            1,
            &ea,
            existing_dacl as *mut _,
            &mut new_dacl as *mut *mut _ as *mut *mut _,
        )
    };

    if !sd.is_null() {
        unsafe { LocalFree(sd) };
    }

    if err != 0 {
        return Err(Error::Process(format!(
            "SetEntriesInAclW({}): error {err}",
            path.display()
        )));
    }

    // Apply the new DACL.
    let err = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr() as *mut _,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl as *const _,
            std::ptr::null(),
        )
    };

    if !new_dacl.is_null() {
        unsafe { LocalFree(new_dacl) };
    }

    if err != 0 {
        return Err(Error::Process(format!(
            "SetNamedSecurityInfoW grant({}): error {err}",
            path.display()
        )));
    }

    Ok(())
}

/// Delete an AppContainer profile by name.
pub fn delete_app_container(name: &str) -> crate::Result<()> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: wide is a valid null-terminated UTF-16 string.
    let hr = unsafe {
        windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile(wide.as_ptr())
    };
    if hr != 0 {
        return Err(Error::Process(format!(
            "DeleteAppContainerProfile({name}): HRESULT 0x{hr:08X}"
        )));
    }
    Ok(())
}

/// Generate a unique AppContainer profile name from task_id and pid.
///
/// AppContainer names are limited to 64 characters. We use a hash
/// to keep within the limit while avoiding collisions.
pub fn container_name(task_id: &str) -> String {
    let pid = std::process::id();
    let hash = fnv1a_64(format!("{task_id}-{pid}").as_bytes());
    format!("arapuca-{hash:016x}")
}

/// Create an AppContainer profile and return its SID.
///
/// The SID must be freed with `FreeSid` when no longer needed.
/// The profile persists in the registry until `delete_app_container`.
pub fn create_app_container(name: &str) -> crate::Result<AppContainerSid> {
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_desc: Vec<u16> = "arapuca sandbox"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut sid: windows_sys::Win32::Security::PSID = std::ptr::null_mut();

    // SAFETY: All strings are valid null-terminated UTF-16.
    let hr = unsafe {
        windows_sys::Win32::Security::Isolation::CreateAppContainerProfile(
            wide_name.as_ptr(),
            wide_name.as_ptr(),
            wide_desc.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        )
    };

    if hr != 0 {
        // HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) = 0x800700B7
        if hr == 0x800700B7u32 as i32 {
            delete_app_container(name)
                .map_err(|e| Error::Process(format!("stale AppContainer profile: {e}")))?;
            // Single retry after deleting the stale profile.
            let mut sid2: windows_sys::Win32::Security::PSID = std::ptr::null_mut();
            let hr2 = unsafe {
                windows_sys::Win32::Security::Isolation::CreateAppContainerProfile(
                    wide_name.as_ptr(),
                    wide_name.as_ptr(),
                    wide_desc.as_ptr(),
                    std::ptr::null(),
                    0,
                    &mut sid2,
                )
            };
            if hr2 != 0 {
                return Err(Error::Process(format!(
                    "CreateAppContainerProfile({name}) retry: HRESULT 0x{hr2:08X}"
                )));
            }
            return Ok(AppContainerSid { sid: sid2 });
        }
        return Err(Error::Process(format!(
            "CreateAppContainerProfile({name}): HRESULT 0x{hr:08X}"
        )));
    }

    Ok(AppContainerSid { sid })
}

/// RAII wrapper for an AppContainer SID allocated by the system.
pub struct AppContainerSid {
    pub sid: windows_sys::Win32::Security::PSID,
}

impl Drop for AppContainerSid {
    fn drop(&mut self) {
        if !self.sid.is_null() {
            // SAFETY: sid was allocated by CreateAppContainerProfile.
            unsafe { windows_sys::Win32::Security::FreeSid(self.sid) };
        }
    }
}

// SAFETY: AppContainerSid holds a system-allocated SID pointer
// accessed only during process creation. Not Sync because concurrent
// reads of the raw pointer would be unsafe.
unsafe impl Send for AppContainerSid {}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_simple() {
        let result = quote_args("cmd", &["arg1", "arg2"]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, "cmd arg1 arg2");
    }

    #[test]
    fn quote_spaces() {
        let result = quote_args("my program", &["hello world", "simple"]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, r#""my program" "hello world" simple"#);
    }

    #[test]
    fn quote_embedded_quotes() {
        let result = quote_args("cmd", &[r#"say "hello""#]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, r#"cmd "say \"hello\"""#);
    }

    #[test]
    fn quote_backslash_before_quote() {
        let result = quote_args("cmd", &[r#"path\"#]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, r"cmd path\");
    }

    #[test]
    fn quote_backslash_before_quote_with_space() {
        let result = quote_args("cmd", &[r#"c:\my dir\"#]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, r#"cmd "c:\my dir\\""#);
    }

    #[test]
    fn quote_windows_path_with_spaces() {
        let result = quote_args("cmd", &[r"C:\Program Files\app"]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, r#"cmd "C:\Program Files\app""#);
    }

    #[test]
    fn quote_empty_arg() {
        let result = quote_args("cmd", &[""]);
        let s: String = result
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, r#"cmd """#);
    }

    #[test]
    fn quote_null_terminated() {
        let result = quote_args("cmd", &[]);
        assert_eq!(*result.last().unwrap(), 0u16);
    }

    #[test]
    fn work_dir_removes_verbatim_disk_prefix() {
        let encoded = encode_work_dir(Path::new(r"\\?\C:\work tree"));
        let decoded = String::from_utf16(&encoded[..encoded.len() - 1]).unwrap();
        assert_eq!(decoded, r"C:\work tree");
    }

    #[test]
    fn work_dir_converts_verbatim_unc_prefix() {
        let encoded = encode_work_dir(Path::new(r"\\?\UNC\server\share\work"));
        let decoded = String::from_utf16(&encoded[..encoded.len() - 1]).unwrap();
        assert_eq!(decoded, r"\\server\share\work");
    }

    #[test]
    fn work_dir_preserves_verbatim_volume_guid_path() {
        let path = r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\work";
        let encoded = encode_work_dir(Path::new(path));
        let decoded = String::from_utf16(&encoded[..encoded.len() - 1]).unwrap();
        assert_eq!(decoded, path);
    }

    #[test]
    fn work_dir_preserves_regular_path_and_terminates() {
        let encoded = encode_work_dir(Path::new(r"C:\work"));
        let decoded = String::from_utf16(&encoded[..encoded.len() - 1]).unwrap();
        assert_eq!(decoded, r"C:\work");
        assert_eq!(encoded.last(), Some(&0));
    }

    #[test]
    fn child_env_sets_local_app_data_to_sandbox_temp() {
        let temp = Path::new(r"C:\sandbox-temp");
        let config = Config {
            profile: crate::Profile::default(),
            socket_dir: PathBuf::new(),
            task_id: "env-test".into(),
            phase: "test".into(),
            work_dir: None,
            network_proxy_socket: None,
            env: Vec::new(),
            audit_sink: None,
            audit_verbosity: crate::audit::AuditVerbosity::Standard,
            audit_principal: None,
            audit_correlation_id: None,
        };
        let env = build_env(&config, temp);
        assert!(
            env.iter()
                .any(|(key, value)| { key == "LOCALAPPDATA" && value == &temp.to_string_lossy() })
        );
    }

    #[test]
    fn caller_local_app_data_does_not_override_sandbox() {
        let temp = Path::new(r"C:\sandbox-temp");
        let config = Config {
            profile: crate::Profile::default(),
            socket_dir: PathBuf::new(),
            task_id: "env-test".into(),
            phase: "test".into(),
            work_dir: None,
            network_proxy_socket: None,
            env: vec![("localappdata".into(), r"C:\Users\host\AppData\Local".into())],
            audit_sink: None,
            audit_verbosity: crate::audit::AuditVerbosity::Standard,
            audit_principal: None,
            audit_correlation_id: None,
        };

        let values: Vec<_> = build_env(&config, temp)
            .into_iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("LOCALAPPDATA"))
            .collect();
        assert_eq!(
            values,
            vec![("LOCALAPPDATA".into(), temp.to_string_lossy().into_owned())]
        );
    }

    #[test]
    fn caller_path_and_user_profile_do_not_override_sandbox() {
        let temp = Path::new(r"C:\sandbox-temp");
        let config = Config {
            profile: crate::Profile::default(),
            socket_dir: PathBuf::new(),
            task_id: "env-test".into(),
            phase: "test".into(),
            work_dir: None,
            network_proxy_socket: None,
            env: vec![
                ("Path".into(), r"C:\host-bin".into()),
                ("userprofile".into(), r"C:\Users\host".into()),
            ],
            audit_sink: None,
            audit_verbosity: crate::audit::AuditVerbosity::Standard,
            audit_principal: None,
            audit_correlation_id: None,
        };

        let env = build_env(&config, temp);
        let paths: Vec<_> = env
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("PATH"))
            .collect();
        assert_eq!(paths.len(), 1);
        assert!(!paths[0].1.contains("host-bin"));

        let profiles: Vec<_> = env
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("USERPROFILE"))
            .collect();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].1, temp.to_string_lossy());
    }

    #[test]
    fn caller_app_data_home_and_username_do_not_override_sandbox() {
        let temp = Path::new(r"C:\sandbox-temp");
        let config = Config {
            profile: crate::Profile::default(),
            socket_dir: PathBuf::new(),
            task_id: "env-test".into(),
            phase: "test".into(),
            work_dir: None,
            network_proxy_socket: None,
            env: vec![
                ("AppData".into(), r"C:\Users\host\AppData\Roaming".into()),
                ("homedrive".into(), "D:".into()),
                ("HomePath".into(), r"\Users\host".into()),
                ("UserName".into(), "host-user".into()),
            ],
            audit_sink: None,
            audit_verbosity: crate::audit::AuditVerbosity::Standard,
            audit_principal: None,
            audit_correlation_id: None,
        };

        let env = build_env(&config, temp);
        let only = |name: &str| -> Vec<_> {
            env.iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .cloned()
                .collect()
        };

        assert_eq!(
            only("APPDATA"),
            vec![("APPDATA".into(), temp.to_string_lossy().into_owned())]
        );
        assert_eq!(only("HOMEDRIVE"), vec![("HOMEDRIVE".into(), "C:".into())]);
        assert_eq!(
            only("HOMEPATH"),
            vec![("HOMEPATH".into(), r"\sandbox-temp".into())]
        );
        assert_eq!(
            only("USERNAME"),
            vec![("USERNAME".into(), "sandbox".into())]
        );
    }

    #[test]
    fn split_windows_home_uses_drive_and_path() {
        assert_eq!(
            split_windows_home(r"C:\sandbox-temp"),
            ("C:".into(), r"\sandbox-temp".into())
        );
        assert_eq!(split_windows_home(r"d:"), ("D:".into(), r"\".into()));
    }

    #[test]
    fn env_block_sorted() {
        let vars = vec![
            ("ZEBRA".into(), "1".into()),
            ("ALPHA".into(), "2".into()),
            ("middle".into(), "3".into()),
        ];
        let block = encode_env_block(&vars);
        let decoded: String = block
            .iter()
            .map(|&c| if c == 0 { '\n' } else { c as u8 as char })
            .collect();
        assert!(decoded.starts_with("ALPHA=2\n"));
        assert!(decoded.contains("middle=3\n"));
        assert!(decoded.contains("ZEBRA=1\n"));
        assert!(decoded.ends_with("\n\n"));
    }

    #[test]
    fn env_block_case_insensitive_sort() {
        let vars = vec![
            ("path".into(), "1".into()),
            ("PATH".into(), "2".into()),
            ("Path".into(), "3".into()),
        ];
        let block = encode_env_block(&vars);
        let decoded: String = block
            .iter()
            .map(|&c| if c == 0 { '\n' } else { c as u8 as char })
            .collect();
        assert!(decoded.starts_with("path=1\n"));
    }

    #[test]
    fn env_block_double_null_terminated() {
        let vars = vec![("A".into(), "1".into())];
        let block = encode_env_block(&vars);
        let len = block.len();
        assert_eq!(block[len - 1], 0);
        assert_eq!(block[len - 2], 0);
    }

    #[test]
    fn env_block_empty() {
        let block = encode_env_block(&[]);
        assert_eq!(block, vec![0u16]);
    }
}
