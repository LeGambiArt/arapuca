//! Explicit security requests must fail rather than degrade on other targets.
#![cfg(not(seccomp_supported))]

#[test]
fn unsupported_policy_fails_before_application() {
    let profile = arapuca::Profile {
        deny_unix_sockets: true,
        ..Default::default()
    };
    assert!(profile.validate_unix_socket_policy().is_err());
    let handle = arapuca::ffi::arapuca_profile_new();
    unsafe {
        arapuca::ffi::arapuca_profile_set_deny_unix_sockets(handle, true);
        assert_eq!(arapuca::ffi::arapuca_apply(handle), -1);
        arapuca::ffi::arapuca_profile_free(handle);
    }
}

#[test]
fn unsupported_cli_never_executes_the_target() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_arapuca"))
        .args(["run", "--no-unix-sockets", "--", "echo", "TARGET_EXECUTED"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("TARGET_EXECUTED"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires Linux"));
}
