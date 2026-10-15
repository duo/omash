use anyhow::{Context, Result, bail};
use std::os::unix::fs::MetadataExt;
use std::{fs, path::Path};

/// Every component of privileged executable/configuration paths must be root-owned.
pub fn trusted_path(path: &Path, executable: bool) -> Result<()> {
    if !path.is_absolute() {
        bail!("privileged path must be absolute");
    }
    for part in path.ancestors() {
        let metadata = fs::symlink_metadata(part)?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            bail!(
                "untrusted ownership, permissions or symlink: {}",
                part.display()
            );
        }
    }
    let metadata = fs::metadata(path)?;
    if !metadata.is_file()
        || (executable && (metadata.mode() & 0o111 == 0 || metadata.mode() & 0o6000 != 0))
    {
        bail!("invalid privileged file: {}", path.display());
    }
    Ok(())
}
pub fn trusted_core() -> Result<()> {
    let core = Path::new("/usr/bin/mihomo");
    trusted_path(core, true)?;
    let output = getcap(["/usr/sbin/getcap", "/usr/bin/getcap"], core)?;
    if !output.status.success() || !output.stdout.is_empty() {
        bail!(
            "Mihomo has file capabilities or cannot be inspected; use an unmodified system package"
        );
    }
    Ok(())
}

fn getcap(programs: [&str; 2], file: &Path) -> Result<std::process::Output> {
    let run = |program| std::process::Command::new(program).arg(file).output();
    run(programs[0])
        .or_else(|_| run(programs[1]))
        .with_context(|| {
            format!(
                "cannot run {} or {} to inspect {}; getcap comes with libcap (libcap2-bin on Debian)",
                programs[0],
                programs[1],
                file.display()
            )
        })
}

pub const HELPER: &str = "/usr/local/libexec/omash-tun-service";
pub const UNIT: &str = "/etc/systemd/system/omash-tun.service";
const UNIT_NAME: &str = "omash-tun.service";

fn linux_only() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("TUN setup requires Linux with systemd");
    }
    Ok(())
}
fn safe_data_dir(path: &Path, uid: u32) -> Result<()> {
    use anyhow::Context;
    let name = path.to_str().context("data path must be UTF-8")?;
    if !name.starts_with('/')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
    {
        bail!(
            "TUN data directory must use an absolute path without whitespace or systemd substitutions"
        );
    }
    if fs::canonicalize(path)? != path || fs::metadata(path)?.uid() != uid {
        bail!("data directory must be canonical and owned by the installing user");
    }
    for part in path.ancestors() {
        let m = fs::symlink_metadata(part)?;
        let symlink = m.file_type().is_symlink();
        if let Some(reason) = unsafe_ancestor(part, symlink, m.uid(), m.mode(), uid) {
            bail!("unsafe TUN data directory ancestry: {reason}");
        }
    }
    Ok(())
}
/// Why one directory on the data path makes it unsafe for the helper, naming the fix when the
/// installing user can apply it.
fn unsafe_ancestor(part: &Path, symlink: bool, owner: u32, mode: u32, uid: u32) -> Option<String> {
    let path = part.display();
    if symlink {
        Some(format!("{path} is a symbolic link"))
    } else if owner != 0 && owner != uid {
        Some(format!(
            "{path} is owned by UID {owner}, not root or UID {uid}"
        ))
    } else if mode & 0o022 != 0 {
        let fix = if owner == uid {
            format!("; run: chmod go-w {path}")
        } else {
            String::new()
        };
        Some(format!("{path} is writable by its group or others{fix}"))
    } else {
        None
    }
}
/// Removes group and other write permission from the data directory, which a umask such as
/// Ubuntu's 0002 leaves when omash creates it. A path that `open_dir_nofollow` refuses is left
/// unchanged, for `safe_data_dir` to judge.
fn private_data_dir(path: &Path, uid: u32) -> Result<bool> {
    let Ok(dir) = open_dir_nofollow(path) else {
        return Ok(false);
    };
    make_private(&dir, uid).with_context(|| {
        format!(
            "cannot remove group and other write permission from {}",
            path.display()
        )
    })
}
/// Opens a directory one component at a time and refuses a symbolic link in any of them, so that
/// what is inspected through the handle is what is changed, even if the path is replaced. The
/// path must be absolute and name every component plainly: no `.`, `..` or empty component.
fn open_dir_nofollow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    // The bytes are split by hand: `Path::components` would quietly drop `.` and repeated slashes.
    let Some(relative) = path.as_os_str().as_bytes().strip_prefix(b"/") else {
        return Err(std::io::ErrorKind::InvalidInput.into());
    };
    let mut dir = fs::File::open("/")?;
    for name in relative.split(|&byte| byte == b'/') {
        if matches!(name, b"" | b"." | b"..") {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let name = std::ffi::CString::new(name)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        dir = unsafe { fs::File::from_raw_fd(fd) };
    }
    Ok(dir)
}
fn make_private(dir: &fs::File, uid: u32) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = dir.metadata()?;
    let mode = metadata.mode() & 0o7777;
    if !metadata.is_dir() || metadata.uid() != uid || mode & 0o022 == 0 {
        return Ok(false);
    }
    dir.set_permissions(fs::Permissions::from_mode(mode & !0o022))?;
    Ok(true)
}
fn target(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing target parent"))?;
    for part in parent.ancestors() {
        let m = fs::symlink_metadata(part)?;
        if m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            bail!("unsafe installation parent {}", part.display());
        }
    }
    if fs::symlink_metadata(path).is_ok() {
        trusted_path(path, false)?;
    }
    Ok(())
}
fn systemctl(args: &[&str]) -> Result<()> {
    let status = std::process::Command::new("/usr/bin/systemctl")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args(args)
        .status()?;
    if !status.success() {
        bail!("systemctl {} failed ({status})", args.join(" "));
    }
    Ok(())
}
fn require_installer(uid: u32) -> Result<()> {
    linux_only()?;
    if unsafe { libc::geteuid() } != 0 || uid == 0 {
        bail!("installer requires root and a non-root service owner");
    }
    if std::env::var("SUDO_UID")
        .or_else(|_| std::env::var("PKEXEC_UID"))
        .ok()
        .as_deref()
        != Some(&uid.to_string())
    {
        bail!("installer UID must match the user who authorized elevation");
    }
    Ok(())
}

pub fn root_install(uid: u32, gid: u32, data_dir: &Path, digest: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    require_installer(uid)?;
    // Numeric User/Group must describe the same account; never grant a caller an unrelated group.
    let account = unsafe { libc::getpwuid(uid) };
    if account.is_null() || unsafe { (*account).pw_gid } != gid {
        bail!("service GID must match the installing user's primary group");
    }
    safe_data_dir(data_dir, uid)?;
    trusted_core()?;
    super::firewall::program()?;
    if Path::new(super::service::SETTINGS).exists() {
        let old = super::service::load_settings()?;
        if old.uid != uid {
            bail!("TUN service belongs to another user; refusing takeover");
        }
    }
    let source = std::env::current_exe()?;
    let bytes = fs::read(&source)?;
    if super::protocol::revision(&bytes) != digest {
        bail!("installer binary changed after authorization");
    }
    // Only this dedicated directory may be created; verify its parent first.
    let parent = Path::new(HELPER).parent().unwrap();
    if !parent.exists() {
        target(parent)?;
        fs::create_dir(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
    }
    for path in [HELPER, UNIT, super::service::SETTINGS] {
        target(Path::new(path))?;
    }
    if Path::new(UNIT).exists() {
        systemctl(&["stop", UNIT_NAME])?;
    }
    super::process::private_write(Path::new(HELPER), &bytes)?;
    fs::set_permissions(HELPER, fs::Permissions::from_mode(0o755))?;
    if super::protocol::revision(&fs::read(HELPER)?) != digest {
        bail!("installed helper digest mismatch");
    }
    let settings = super::service::Settings {
        uid,
        gid,
        data_dir: data_dir.to_path_buf(),
    };
    super::process::private_write(
        Path::new(super::service::SETTINGS),
        &serde_json::to_vec(&settings)?,
    )?;
    fs::set_permissions(super::service::SETTINGS, fs::Permissions::from_mode(0o644))?;
    let unit = render_unit(&settings)?;
    super::process::private_write(Path::new(UNIT), unit.as_bytes())?;
    fs::set_permissions(UNIT, fs::Permissions::from_mode(0o644))?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", UNIT_NAME])?;
    Ok(())
}

fn render_unit(settings: &super::service::Settings) -> Result<String> {
    use anyhow::Context;
    let data = settings
        .data_dir
        .to_str()
        .context("invalid data directory")?;
    Ok(include_str!("../../systemd/omash-tun.service")
        .replace("@UID@", &settings.uid.to_string())
        .replace("@GID@", &settings.gid.to_string())
        .replace("@DATA@", data))
}

pub fn root_uninstall(uid: u32) -> Result<()> {
    require_installer(uid)?;
    let settings = super::service::load_settings()?;
    if settings.uid != uid {
        bail!("TUN helper belongs to another user");
    }
    for path in [HELPER, UNIT, super::service::SETTINGS] {
        target(Path::new(path))?;
    }
    // systemd waits for all processes in the unit cgroup before removal.
    systemctl(&["disable", "--now", UNIT_NAME])?;
    for path in [UNIT, HELPER, super::service::SETTINGS] {
        fs::remove_file(path)?;
    }
    systemctl(&["daemon-reload"])?;
    Ok(())
}

pub async fn setup() -> Result<()> {
    install_helper().await?;
    let uid = unsafe { libc::geteuid() };
    println!("TUN helper installed for UID {uid}. Enable with: omash tun on");
    Ok(())
}

/// Installs or updates the helper through sudo or pkexec and confirms that it answers; `setup`
/// and the TUI's Settings page differ only in what they say afterwards.
pub async fn install_helper() -> Result<()> {
    linux_only()?;
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    if uid == 0 {
        bail!("run `omash tun setup` as your normal desktop user");
    }
    let dir = crate::config::Config::data_dir();
    fs::create_dir_all(&dir)?;
    if private_data_dir(&dir, uid)? {
        println!(
            "Made {} writable only by you, as the TUN helper requires.",
            dir.display()
        );
    }
    safe_data_dir(&dir, uid)?;
    let exe = std::env::current_exe()?;
    let digest = super::protocol::revision(&fs::read(&exe)?);
    let status = elevate(&exe)?
        .arg("internal-tun-install")
        .arg(uid.to_string())
        .arg(gid.to_string())
        .arg(&dir)
        .arg(&digest)
        .status()
        .await?;
    if !status.success() {
        bail!("TUN setup failed ({status})");
    }
    // Confirm the newly installed helper, including its registered data directory.
    let mut connected = false;
    for _ in 0..30 {
        if super::protocol::Client::connect().await.is_ok() {
            connected = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    if !connected {
        bail!(
            "helper installed but did not answer; inspect `systemctl status omash-tun` and `omash tun doctor`"
        );
    }
    // When the installer cannot confirm the old helper, it leaves the supervisor running the
    // replaced binary, which would keep using the previous helper protocol.
    match crate::core::supervisor_runs_replaced_binary().await {
        Ok(false) => {}
        Ok(true) => {
            use anyhow::Context;
            crate::core::restart_supervisor().await.context(
                "helper installed, but the supervisor still runs a replaced omash binary and could not be restarted; run `systemctl --user restart omash-supervisor.service`",
            )?;
            println!("Restarted the supervisor, which was still running a replaced omash binary.");
        }
        Err(error) => eprintln!(
            "Cannot check whether the supervisor runs a replaced omash binary ({error:#}); if TUN reports a protocol mismatch, run `systemctl --user restart omash-supervisor.service`."
        ),
    }
    Ok(())
}
fn elevate(exe: &Path) -> Result<tokio::process::Command> {
    use std::io::IsTerminal;
    let mut c = if std::io::stdin().is_terminal() || !Path::new("/usr/bin/pkexec").is_file() {
        let mut c = tokio::process::Command::new("/usr/bin/sudo");
        if !std::io::stdin().is_terminal() {
            c.arg("-n");
        }
        c
    } else {
        tokio::process::Command::new("/usr/bin/pkexec")
    };
    c.arg(exe);
    Ok(c)
}
pub async fn uninstall(config: &mut crate::config::Config) -> Result<()> {
    linux_only()?;
    if !Path::new(super::service::SETTINGS).exists() {
        println!("TUN helper is not installed");
        return Ok(());
    }
    let uid = unsafe { libc::geteuid() };
    if super::service::load_settings()?.uid != uid {
        bail!("run `omash tun uninstall` as the user who installed the helper");
    }
    let has_profiles = !crate::profiles::Profiles::load()?.items.is_empty();
    // Complete the backend switch before removing the service it needs to stop.
    config.tun_enabled = false;
    config.save()?;
    crate::core::request_restart()?;
    let request = super::toggle::Request::new(crate::core::desired_revision(), false);
    crate::core::ensure_supervisor(config.auto_start).await?;
    super::cli::wait_for_uninstall(request, has_profiles).await?;
    // Only the helper retries a failed removal of its firewall exceptions.
    super::cli::wait_for_firewall_cleanup().await?;
    let status = elevate(&std::env::current_exe()?)?
        .arg("internal-tun-uninstall")
        .arg(uid.to_string())
        .status()
        .await?;
    if !status.success() {
        bail!("TUN helper uninstall failed ({status})");
    }
    println!("TUN helper removed; profiles and data preserved");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_getcap_names_the_tool() {
        let programs = ["/nonexistent/sbin/getcap", "/nonexistent/bin/getcap"];
        let error = getcap(programs, Path::new("/usr/bin/mihomo")).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("getcap") && text.contains("libcap"), "{text}");
    }
    #[test]
    fn installer_rejects_symlink_target() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("helper");
        std::os::unix::fs::symlink("/usr/bin/true", &link).unwrap();
        assert!(trusted_path(&link, true).is_err());
    }
    #[test]
    fn helper_rejects_untrusted_executable() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("core");
        fs::write(&file, b"not trusted").unwrap();
        assert!(trusted_path(&file, true).is_err());
    }
    #[test]
    fn unsafe_ancestry_names_the_reason() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let uid = fs::metadata(&root).unwrap().uid();
        let parent = root.join("parent");
        let data = parent.join("omash");
        fs::create_dir_all(&data).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o775)).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();
        // The check stops at `parent`, before the machine's own ancestors such as /tmp.
        let error = safe_data_dir(&data, uid).unwrap_err().to_string();
        let parent = parent.display();
        assert_eq!(
            error,
            format!(
                "unsafe TUN data directory ancestry: {parent} is writable by its group or others; run: chmod go-w {parent}"
            )
        );
    }
    #[test]
    fn group_writable_data_directory_is_made_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let uid = fs::metadata(&root).unwrap().uid();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        for (before, after) in [(0o775, 0o755), (0o770, 0o750), (0o777, 0o755)] {
            let data = root.join(format!("{before:o}"));
            fs::create_dir(&data).unwrap();
            fs::set_permissions(&data, fs::Permissions::from_mode(before)).unwrap();
            assert!(private_data_dir(&data, uid).unwrap());
            assert_eq!(mode(&data), after);
            assert!(!private_data_dir(&data, uid).unwrap());
        }
        let private = root.join("private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!private_data_dir(&private, uid).unwrap());
        assert_eq!(mode(&private), 0o700);
    }
    #[test]
    fn only_the_owners_real_directory_is_changed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let uid = fs::metadata(&root).unwrap().uid();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        let real = root.join("real");
        let data = real.join("omash");
        fs::create_dir_all(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o775)).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&data, &link).unwrap();
        let through = root.join("through");
        std::os::unix::fs::symlink(&real, &through).unwrap();
        assert!(!private_data_dir(&link, uid).unwrap());
        assert!(!private_data_dir(&through.join("omash"), uid).unwrap());
        assert!(!private_data_dir(&data, uid.wrapping_add(1)).unwrap());
        assert_eq!(mode(&data), 0o775);
        let file = root.join("file");
        fs::write(&file, b"").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(!private_data_dir(&file, uid).unwrap());
        assert_eq!(mode(&file), 0o664);
    }
    #[test]
    fn data_directory_is_opened_without_following_links() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let real = root.join("real");
        let data = real.join("omash");
        fs::create_dir_all(&data).unwrap();
        let opened = open_dir_nofollow(&data).unwrap();
        assert_eq!(
            opened.metadata().unwrap().ino(),
            fs::metadata(&data).unwrap().ino()
        );
        let link = root.join("link");
        std::os::unix::fs::symlink(&data, &link).unwrap();
        assert!(open_dir_nofollow(&link).is_err());
        let through = root.join("through");
        std::os::unix::fs::symlink(&real, &through).unwrap();
        assert!(open_dir_nofollow(&through.join("omash")).is_err());
        // Spelled out, since `Path::components` would quietly drop `.` and repeated slashes.
        let spelled =
            |path: &Path, rest: &str| std::path::PathBuf::from(format!("{}{rest}", path.display()));
        for path in [
            Path::new("real/omash").to_path_buf(),
            real.join("../real/omash"),
            real.join("./omash"),
            data.join("."),
            spelled(&real, "//omash"),
            spelled(&data, "/"),
        ] {
            let error = open_dir_nofollow(&path).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{path:?}");
        }
    }
    #[test]
    fn a_replaced_data_directory_does_not_redirect_the_change() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let uid = fs::metadata(&root).unwrap().uid();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        let data = root.join("omash");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o775)).unwrap();
        let secret = root.join("secret");
        fs::write(&secret, b"").unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        let opened = open_dir_nofollow(&data).unwrap();
        // Another account replaces the path after it was opened.
        let moved = root.join("moved");
        fs::rename(&data, &moved).unwrap();
        std::os::unix::fs::symlink(&secret, &data).unwrap();
        assert!(make_private(&opened, uid).unwrap());
        assert_eq!(mode(&moved), 0o755);
        assert_eq!(mode(&secret), 0o600);
    }
    #[test]
    fn ancestor_reasons() {
        let part = Path::new("/home/user/.local");
        let reason = |symlink, owner, mode| unsafe_ancestor(part, symlink, owner, mode, 1000);
        assert_eq!(
            reason(true, 1000, 0o777).as_deref(),
            Some("/home/user/.local is a symbolic link")
        );
        assert_eq!(
            reason(false, 1001, 0o755).as_deref(),
            Some("/home/user/.local is owned by UID 1001, not root or UID 1000")
        );
        assert_eq!(
            reason(false, 1000, 0o775).as_deref(),
            Some(
                "/home/user/.local is writable by its group or others; run: chmod go-w /home/user/.local"
            )
        );
        assert_eq!(
            reason(false, 0, 0o1777).as_deref(),
            Some("/home/user/.local is writable by its group or others")
        );
        assert_eq!(reason(false, 0, 0o755), None);
        assert_eq!(reason(false, 1000, 0o750), None);
    }
    #[test]
    fn service_unit_limits_capabilities() {
        let unit = render_unit(&super::super::service::Settings {
            uid: 1000,
            gid: 1000,
            data_dir: "/home/test/data".into(),
        })
        .unwrap();
        assert!(unit.contains("User=1000\n"));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\n"));
        assert!(unit.contains("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\n"));
        assert!(unit.contains("NoNewPrivileges=yes\n"));
        assert!(unit.contains("ReadWritePaths=/home/test/data\n"));
        for directive in [
            "SystemCallArchitectures=native\n",
            "SystemCallFilter=@system-service\n",
            "SystemCallErrorNumber=EPERM\n",
            "RestrictNamespaces=yes\n",
            "MemoryDenyWriteExecute=yes\n",
            "ProtectClock=yes\n",
            "ProtectHostname=yes\n",
            "ProtectKernelLogs=yes\n",
            "PrivateIPC=yes\n",
            "DevicePolicy=closed\n",
            "DeviceAllow=/dev/net/tun rw\n",
        ] {
            assert!(unit.contains(directive), "missing {directive:?}");
        }
        // Only the TUN node may be opened; the core still needs the host network and its own /proc.
        assert_eq!(unit.matches("DeviceAllow=").count(), 1);
        for directive in ["PrivateDevices=", "PrivateNetwork=", "ProtectProc="] {
            assert!(!unit.contains(directive), "unexpected {directive}");
        }
        for placeholder in ["@UID@", "@GID@", "@DATA@"] {
            assert!(!unit.contains(placeholder), "unreplaced {placeholder}");
        }
    }
}
