use std::{process::Command, thread, time::Duration};

#[allow(unsafe_code)]
fn require_root() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "target smoke tests require root"
    );
}

#[test]
#[ignore = "requires the configured root/systemd target with real NVMe devices"]
#[allow(unsafe_code)]
fn daemon_crosses_a_utc_boundary_and_stops_cleanly() {
    require_root();
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_nvme-disk-mon"))
        .spawn()
        .expect("start daemon");
    thread::sleep(Duration::from_secs(70));

    let stats = Command::new(env!("CARGO_BIN_EXE_nvme-disk-mon"))
        .arg("stats")
        .status()
        .expect("run stats");
    assert!(stats.success());

    let result = unsafe {
        libc::kill(
            i32::try_from(daemon.id()).expect("pid fits i32"),
            libc::SIGTERM,
        )
    };
    assert_eq!(result, 0, "send SIGTERM");
    assert!(daemon.wait().expect("wait for daemon").success());
}

#[test]
#[ignore = "sends a real message using the target's configured mail account"]
fn configured_mail_test_send_is_accepted() {
    require_root();
    let status = Command::new(env!("CARGO_BIN_EXE_nvme-disk-mon"))
        .args(["mail", "test-send"])
        .status()
        .expect("run mail test-send");
    assert!(status.success());
}
