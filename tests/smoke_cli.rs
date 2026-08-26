use std::process::Command;

#[test]
fn help_and_version_do_not_require_configuration() {
    for (argument, expected) in [
        ("help", "Usage: nvme-disk-mon"),
        ("version", env!("CARGO_PKG_VERSION")),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_nvme-disk-mon"))
            .arg(argument)
            .output()
            .expect("run binary");
        assert!(
            output.status.success(),
            "{argument} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(expected),
            "{argument} output did not contain {expected:?}: {stdout}"
        );
    }
}
