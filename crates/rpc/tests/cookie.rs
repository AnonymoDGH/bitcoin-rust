use std::fs;
use std::path::PathBuf;

use btc_rpc::write_cookie;

fn fresh_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("btc-rpc-{tag}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn cookie_file_matches_returned_credentials() {
    let dir = fresh_dir("cookie");
    let (user, password) = write_cookie(&dir).unwrap();
    assert_eq!(user, "__cookie__");
    assert_eq!(password.len(), 64);
    assert!(password
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));

    let contents = fs::read_to_string(dir.join(".cookie")).unwrap();
    assert_eq!(contents, format!("__cookie__:{password}"));
    assert!(!dir.join(".cookie.tmp").exists());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn each_call_generates_a_new_password() {
    let dir = fresh_dir("cookie-rotate");
    let first = write_cookie(&dir).unwrap().1;
    let second = write_cookie(&dir).unwrap().1;
    assert_ne!(first, second);
    let contents = fs::read_to_string(dir.join(".cookie")).unwrap();
    assert_eq!(contents, format!("__cookie__:{second}"));
    fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn cookie_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = fresh_dir("cookie-perms");
    write_cookie(&dir).unwrap();
    let mode = fs::metadata(dir.join(".cookie"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    fs::remove_dir_all(&dir).unwrap();
}
