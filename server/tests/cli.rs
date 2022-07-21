#[test]
fn wrong_command() {
    let mut cmd = assert_cmd::Command::cargo_bin("atomic-server").unwrap();
    cmd.args(&["non-existent-command"]).assert().failure();
}

#[test]
fn help() {
    let mut cmd = assert_cmd::Command::cargo_bin("atomic-server").unwrap();
    cmd.args(&["help"]).assert().success();
}

// #[test]
// fn import_file() {
//     let mut cmd = assert_cmd::Command::cargo_bin("atomic-server").unwrap();
//     cmd.current_dir(".").unwrap();
//     cmd.args(&["import", "--file", "./lib/test_files/local_id.json"])
//         .assert()
//         .success();
// }
