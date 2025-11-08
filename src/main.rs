#[cfg(not(target_os = "linux"))]
compile_error!("elevate only supports Linux.");

use std::borrow::Cow;
use std::env;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use zeroize::Zeroize;

const SECURE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const AUTH_MAX_ATTEMPTS: u8 = 3;
const AUTH_BACKOFF_SECONDS: u64 = 1;

#[link(name = "crypt")]
unsafe extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(err) => {
            eprintln!("elevate: {}", err.message);
            std::process::exit(err.code);
        }
    }
}

fn run() -> Result<(), ElevateError> {
    let (command, args) = parse_command_line()?;
    ensure_setuid_root()?;
    authenticate_user()?;
    adopt_full_root_identity()?;
    set_default_umask();

    let resolved = resolve_command(&command)?;
    let env_vars = sanitized_environment();
    exec_command(&resolved, &args, &env_vars)
}

#[derive(Debug)]
struct ElevateError {
    code: i32,
    message: String,
}

impl ElevateError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
        }
    }

    fn with_code(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn parse_command_line() -> Result<(OsString, Vec<OsString>), ElevateError> {
    let mut args = env::args_os();
    let _ = args.next(); // binary name

    let command = loop {
        match args.next() {
            Some(arg) if arg == "--" => continue,
            Some(arg) => break arg,
            None => {
                return Err(ElevateError::with_code(
                    64,
                    "no command provided. usage: elevate <command> [args...]",
                ));
            }
        }
    };

    let remaining: Vec<OsString> = args.collect();
    Ok((command, remaining))
}

fn ensure_setuid_root() -> Result<(), ElevateError> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Err(ElevateError::new(
            "insufficient privileges. install elevate with owner root and the setuid bit (chmod 4755)",
        ));
    }
    Ok(())
}

fn authenticate_user() -> Result<(), ElevateError> {
    let ruid = unsafe { libc::getuid() };
    if ruid == 0 {
        return Ok(());
    }

    let username = lookup_username(ruid)?;
    let shadow_hash = lookup_shadow_hash(&username)?;
    if shadow_hash.is_empty() || matches!(shadow_hash.as_bytes()[0], b'!' | b'*') {
        return Err(ElevateError::new(format!(
            "account '{}' is locked or lacks a usable password",
            username
        )));
    }

    for attempt in 1..=AUTH_MAX_ATTEMPTS {
        let prompt = format!("Password for {}: ", username);
        let mut password = rpassword::prompt_password(prompt)
            .map_err(|err| ElevateError::new(format!("failed to read password: {err}")))?;
        let verified = verify_password(&password, &shadow_hash)?;
        password.zeroize();

        if verified {
            return Ok(());
        }

        eprintln!("elevate: authentication failure");
        if attempt < AUTH_MAX_ATTEMPTS {
            thread::sleep(Duration::from_secs(AUTH_BACKOFF_SECONDS));
        }
    }

    Err(ElevateError::with_code(1, "authentication failure"))
}

fn adopt_full_root_identity() -> Result<(), ElevateError> {
    // SAFETY: All operations require effective UID 0, which we have already verified.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(ElevateError::new(format!(
                "failed to drop supplementary groups: {}",
                io::Error::last_os_error()
            )));
        }
        if libc::setresgid(0, 0, 0) != 0 {
            return Err(ElevateError::new(format!(
                "failed to adopt root group: {}",
                io::Error::last_os_error()
            )));
        }
        if libc::setresuid(0, 0, 0) != 0 {
            return Err(ElevateError::new(format!(
                "failed to adopt root user: {}",
                io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

fn set_default_umask() {
    // SAFETY: Setting umask is safe and local to this process.
    unsafe {
        libc::umask(0o022);
    }
}

fn resolve_command(command: &OsStr) -> Result<PathBuf, ElevateError> {
    if contains_slash(command) {
        let path = PathBuf::from(command);
        ensure_executable(&path)?;
        return Ok(path);
    }

    for dir in SECURE_PATH.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join(command);
        if is_executable(&candidate)? {
            return Ok(candidate);
        }
    }

    Err(ElevateError::with_code(
        127,
        format!(
            "command '{}' not found in secure PATH ({SECURE_PATH})",
            display_os(command)
        ),
    ))
}

fn ensure_executable(path: &Path) -> Result<(), ElevateError> {
    match fs::metadata(path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(ElevateError::with_code(
                    126,
                    format!("'{}' is not a regular file", path.display()),
                ));
            }

            if meta.permissions().mode() & 0o111 == 0 {
                return Err(ElevateError::with_code(
                    126,
                    format!("'{}' is not executable", path.display()),
                ));
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Err(ElevateError::with_code(
            127,
            format!("command '{}' not found", path.display()),
        )),
        Err(err) => Err(ElevateError::new(format!(
            "failed to inspect '{}': {err}",
            path.display()
        ))),
    }
}

fn is_executable(path: &Path) -> Result<bool, ElevateError> {
    match fs::metadata(path) {
        Ok(meta) => Ok(meta.is_file() && meta.permissions().mode() & 0o111 != 0),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(ElevateError::new(format!(
            "failed to inspect '{}': {err}",
            path.display()
        ))),
    }
}

fn exec_command(
    path: &Path,
    args: &[OsString],
    env_vars: &[(OsString, OsString)],
) -> Result<(), ElevateError> {
    let mut command = Command::new(path);
    command.args(args);
    command.env_clear();
    for (key, value) in env_vars {
        command.env(key, value);
    }

    let err = command.exec();
    let code = match err.raw_os_error() {
        Some(libc::ENOENT) => 127,
        Some(libc::EACCES) | Some(libc::EPERM) => 126,
        _ => 1,
    };
    Err(ElevateError::with_code(
        code,
        format!("failed to exec '{}': {err}", path.display()),
    ))
}

fn sanitized_environment() -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("HOME"), OsString::from("/root")),
        (OsString::from("LOGNAME"), OsString::from("root")),
        (OsString::from("USER"), OsString::from("root")),
        (OsString::from("SHELL"), OsString::from("/bin/sh")),
        (OsString::from("LANG"), OsString::from("C.UTF-8")),
        (OsString::from("PATH"), OsString::from(SECURE_PATH)),
        (OsString::from("TERM"), sanitized_term()),
    ]
}

fn sanitized_term() -> OsString {
    match env::var("TERM") {
        Ok(term) if is_safe_term_value(&term) => OsString::from(term),
        _ => OsString::from("xterm-256color"),
    }
}

fn is_safe_term_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '.'))
}

fn contains_slash(value: &OsStr) -> bool {
    value.as_bytes().contains(&b'/')
}

fn display_os(value: &OsStr) -> Cow<'_, str> {
    value.to_string_lossy()
}

fn lookup_username(uid: libc::uid_t) -> Result<String, ElevateError> {
    unsafe {
        let pwd = libc::getpwuid(uid);
        if pwd.is_null() {
            return Err(ElevateError::new(format!(
                "unable to resolve user id {}",
                uid
            )));
        }
        Ok(CStr::from_ptr((*pwd).pw_name)
            .to_string_lossy()
            .into_owned())
    }
}

fn lookup_shadow_hash(username: &str) -> Result<String, ElevateError> {
    let cname = CString::new(username)
        .map_err(|_| ElevateError::new("username contains interior null bytes"))?;
    unsafe {
        libc::setspent();
        let shadow = libc::getspnam(cname.as_ptr());
        libc::endspent();
        if shadow.is_null() {
            return Err(ElevateError::new(format!(
                "unable to locate shadow entry for '{}'",
                username
            )));
        }
        let pwd_ptr = (*shadow).sp_pwdp;
        if pwd_ptr.is_null() {
            return Err(ElevateError::new(format!(
                "shadow entry for '{}' lacks a password field",
                username
            )));
        }
        Ok(CStr::from_ptr(pwd_ptr).to_string_lossy().into_owned())
    }
}

fn verify_password(password: &str, expected_hash: &str) -> Result<bool, ElevateError> {
    if password.is_empty() {
        return Ok(false);
    }

    let c_password = CString::new(password)
        .map_err(|_| ElevateError::new("password contains interior null bytes"))?;
    let c_salt = CString::new(expected_hash)
        .map_err(|_| ElevateError::new("stored password contains interior null bytes"))?;

    let hash_ptr = unsafe { crypt(c_password.as_ptr(), c_salt.as_ptr()) };
    if hash_ptr.is_null() {
        return Err(ElevateError::new(
            "system crypt(3) refused to process the password",
        ));
    }

    let computed = unsafe { CStr::from_ptr(hash_ptr) }
        .to_string_lossy()
        .into_owned();
    Ok(computed == expected_hash)
}
