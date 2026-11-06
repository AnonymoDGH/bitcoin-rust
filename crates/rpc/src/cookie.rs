//! Cookie authentication (`GenerateAuthCookie` in Core's `rpc/request.cpp`).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use bitcoin::hex::DisplayHex;

const COOKIE_USER: &str = "__cookie__";
const COOKIE_FILE: &str = ".cookie";

/// Writes `<datadir>/.cookie` containing `__cookie__:<64 hex chars>` with mode 0600
/// and returns the `(user, password)` pair that clients must present.
pub fn write_cookie(datadir: &Path) -> io::Result<(String, String)> {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).map_err(io::Error::other)?;
    let password = secret.to_lower_hex_string();

    let tmp = datadir.join(format!("{COOKIE_FILE}.tmp"));
    let _ = fs::remove_file(&tmp);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(format!("{COOKIE_USER}:{password}").as_bytes())?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, datadir.join(COOKIE_FILE))?;
    Ok((COOKIE_USER.to_owned(), password))
}
