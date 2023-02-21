#[cfg(test)]
mod test {
    use assert_cmd::Command;

    #[test]
    fn get_fail() {
        let mut cmd = Command::cargo_bin(assert_cmd::crate_name!()).unwrap();
        cmd.args(["get", "random-non-existent-shortname"])
            .assert()
            .failure();
    }

    #[test]
    fn get_shortname() {
        let mut cmd = Command::cargo_bin(assert_cmd::crate_name!()).unwrap();
        cmd.args(["get", "shortname"]).assert().success();
    }

    #[test]
    fn get_url() {
        let mut cmd = Command::cargo_bin(assert_cmd::crate_name!()).unwrap();
        cmd.args(["get", "https://atomicdata.dev/classes"])
            .assert()
            .success();
    }

    #[test]
    fn get_path() {
        let mut cmd = Command::cargo_bin(assert_cmd::crate_name!()).unwrap();
        cmd.args(["get", "https://atomicdata.dev/classes members"])
            .assert()
            .success();
    }

    #[test]
    fn get_path_array() {
        let mut cmd = Command::cargo_bin(assert_cmd::crate_name!()).unwrap();
        cmd.args(["get", "https://atomicdata.dev/classes is-a 0"])
            .assert()
            .success();
    }

    #[test]
    fn get_path_array_non_existent() {
        let mut cmd = Command::cargo_bin(assert_cmd::crate_name!()).unwrap();
        cmd.args(["get", "https://atomicdata.dev/classes is-a 1"])
            .assert()
            .failure();
    }

    #[ignore]
    #[test]
    fn set_and_get() {
        use std::time::SystemTime;
        let value: String = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let mut cmd_set = Command::cargo_bin(assert_cmd::crate_name!()).unwrap();
        cmd_set
            .args([
                "set",
                "https://atomicdata.dev/test",
                atomic_lib::urls::SHORTNAME,
                &value,
            ])
            .assert()
            .success();

        let mut cmd_get = Command::cargo_bin(assert_cmd::crate_name!()).unwrap();
        let result = cmd_get
            .args(["get", "https://atomicdata.dev/test shortname"])
            .assert()
            .success()
            .to_string();
        assert!(result.contains(&value));
    }
}
