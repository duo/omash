use crate::{
    api::MihomoClient,
    config::Config,
    profiles::{CoreKind, Profiles},
};
use anyhow::{Context, Result, bail};
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant, SystemTime},
};
use tokio::process::{Child, Command};

const VALIDATION_TIMEOUT: Duration = Duration::from_secs(30);
const CORE_READINESS_ATTEMPTS: usize = 30;
const CORE_READINESS_INTERVAL: Duration = Duration::from_millis(100);
const CORE_READINESS_PROBE_TIMEOUT: Duration = Duration::from_millis(400);
const START_RETRY_BACKOFF: Duration = Duration::from_secs(5);

pub enum ConfigApply {
    Reloaded,
    Restarted,
}

pub struct CoreManager {
    child: Option<Child>,
}

impl CoreManager {
    pub const fn new() -> Self {
        Self { child: None }
    }

    pub async fn validate(&self, config: &Config, profiles: &Profiles) -> Result<()> {
        self.validate_runtime(config, profiles, true).await
    }

    pub async fn validate_only(&self, config: &Config, profiles: &Profiles) -> Result<()> {
        self.validate_runtime(config, profiles, false).await
    }

    async fn validate_runtime(
        &self,
        config: &Config,
        profiles: &Profiles,
        commit: bool,
    ) -> Result<()> {
        let core = profiles.current_core();
        if core == CoreKind::Mihomo {
            ensure_core_resources()?;
        }
        let runtime = Config::runtime_path_for(core);
        let staged = staged_runtime_path(core);
        profiles.build_runtime_at(config, &staged)?;
        Self::check_runtime(core, &staged).await?;
        if commit {
            fs::rename(&staged, &runtime).with_context(|| {
                format!("failed to commit validated runtime {}", runtime.display())
            })?;
        } else {
            fs::remove_file(&staged)?;
        }
        Ok(())
    }

    async fn check_runtime(core: CoreKind, staged: &Path) -> Result<()> {
        let mut command = Command::new(Config::core_path(core));
        match core {
            CoreKind::Mihomo => {
                command
                    .args(["-t", "-d"])
                    .arg(Config::data_dir())
                    .arg("-f")
                    .arg(staged);
            }
            CoreKind::Singbox => {
                command
                    .args(["check", "-c"])
                    .arg(staged)
                    .arg("-D")
                    .arg(Config::data_dir())
                    .arg("--disable-color");
            }
        }
        command.kill_on_drop(true);
        let output = match tokio::time::timeout(VALIDATION_TIMEOUT, command.output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                let _ = fs::remove_file(staged);
                return Err(error).context(format!("failed to execute {} validator", core.as_str()));
            }
            Err(_) => {
                let _ = fs::remove_file(staged);
                bail!(
                    "{} configuration validation timed out after 30 seconds",
                    core.as_str()
                );
            }
        };
        if !output.status.success() {
            let _ = fs::remove_file(staged);
            bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
        }
        Ok(())
    }

    pub async fn start(&mut self, config: &Config, profiles: &Profiles) -> Result<()> {
        if self.is_running() {
            return Ok(());
        }
        self.validate(config, profiles).await?;
        self.start_validated(config, profiles).await
    }

    async fn start_validated(&mut self, config: &Config, profiles: &Profiles) -> Result<()> {
        let core = profiles.current_core();
        let log_path = Config::logs_dir().join(format!(
            "{}-{}.log",
            core.as_str(),
            Local::now().format("%Y-%m-%d")
        ));
        let stdout = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let stderr = stdout.try_clone()?;
        let runtime = Config::runtime_path_for(core);
        let mut command = Command::new(Config::core_path(core));
        match core {
            CoreKind::Mihomo => {
                command
                    .arg("-d")
                    .arg(Config::data_dir())
                    .arg("-f")
                    .arg(&runtime);
            }
            CoreKind::Singbox => {
                command
                    .args(["run", "-c"])
                    .arg(&runtime)
                    .arg("-D")
                    .arg(Config::data_dir())
                    .arg("--disable-color");
            }
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .kill_on_drop(true)
            .spawn()
            .context(format!("failed to start {}", core.as_str()))?;

        let api = MihomoClient::new(&config.controller, config.secret.clone())?;
        let mut last_error = format!("{} API did not answer", core.as_str());
        let mut ready = false;
        for attempt in 0..CORE_READINESS_ATTEMPTS {
            if let Some(status) = child.try_wait()? {
                bail!(
                    "{} exited during startup with {status}; see {}",
                    core.as_str(),
                    log_path.display()
                );
            }
            match tokio::time::timeout(CORE_READINESS_PROBE_TIMEOUT, api.version()).await {
                Ok(Ok(_)) => {
                    ready = true;
                    break;
                }
                Ok(Err(error)) => last_error = error.to_string(),
                Err(_) => last_error = "readiness probe timed out".into(),
            }
            if attempt + 1 < CORE_READINESS_ATTEMPTS {
                tokio::time::sleep(CORE_READINESS_INTERVAL).await;
            }
        }
        if !ready {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
            bail!(
                "{} API did not become ready: {last_error}; see {}",
                core.as_str(),
                log_path.display()
            );
        }
        self.child = Some(child);
        let _ = restore_selected_nodes(config, profiles).await;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            child.start_kill()?;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(3), child.wait()).await;
        }
        Ok(())
    }

    pub async fn restart(&mut self, config: &Config, profiles: &Profiles) -> Result<ConfigApply> {
        let core = profiles.current_core();
        if core == CoreKind::Mihomo {
            ensure_core_resources()?;
        }
        let runtime = Config::runtime_path_for(core);
        let staged = staged_runtime_path(core);
        profiles.build_runtime_at(config, &staged)?;
        // Selection changes only rewrite profiles.yaml; when the rebuilt
        // runtime config is identical, keep the running core and re-apply the
        // stored selections instead of bouncing the process.
        if runtime.is_file() && fs::read(&runtime)? == fs::read(&staged)? {
            fs::remove_file(&staged)?;
            let _ = restore_selected_nodes(config, profiles).await;
            return Ok(ConfigApply::Reloaded);
        }
        Self::check_runtime(core, &staged).await?;
        fs::rename(&staged, &runtime)
            .with_context(|| format!("failed to commit validated runtime {}", runtime.display()))?;
        // sing-box's Clash API ignores mihomo's `path` reload extension, so it
        // always needs a process restart to pick up a new runtime config.
        if core == CoreKind::Mihomo {
            let api = MihomoClient::new(&config.controller, config.secret.clone())?;
            if api.reload_config(&runtime).await.is_ok() {
                let _ = restore_selected_nodes(config, profiles).await;
                return Ok(ConfigApply::Reloaded);
            }
        }
        self.stop().await?;
        self.start_validated(config, profiles).await?;
        Ok(ConfigApply::Restarted)
    }

    pub fn is_running(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|child| matches!(child.try_wait(), Ok(None)))
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().and_then(Child::id)
    }

    pub fn recent_logs(limit: usize) -> Result<Vec<String>> {
        let Some(path) = fs::read_dir(Config::logs_dir())?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "log"))
            .max_by_key(|path| fs::metadata(path).and_then(|m| m.modified()).ok())
        else {
            return Ok(vec![]);
        };
        let text = fs::read_to_string(path)?;
        let mut lines: Vec<_> = text.lines().rev().take(limit).map(str::to_owned).collect();
        lines.reverse();
        Ok(lines)
    }
}

fn staged_runtime_path(core: CoreKind) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    Config::runtime_path_for(core).with_file_name(format!(
        "runtime.pending-{}-{nonce}.{}",
        std::process::id(),
        core.extension()
    ))
}

pub fn ensure_system_core() -> Result<()> {
    let profiles = Profiles::load().unwrap_or_default();
    if profiles.items.is_empty() {
        return Ok(());
    }
    let core = profiles.current_core();
    let path = Config::core_path(core);
    if !path.is_file() {
        bail!(
            "system {} not found at {}; install the Arch {} package",
            core.as_str(),
            path.display(),
            core.as_str()
        );
    }
    Ok(())
}

async fn restore_selected_nodes(config: &Config, profiles: &Profiles) -> Result<()> {
    let selected = profiles.current_selections();
    if selected.is_empty() {
        return Ok(());
    }
    let api = MihomoClient::new(&config.controller, config.secret.clone())?;
    let proxies = api.proxies().await?;
    for selection in selected {
        let Some(group) = proxies.proxies.get(&selection.name) else {
            continue;
        };
        if group.all.iter().any(|node| node == &selection.now) && group.now != selection.now {
            api.select_proxy(&selection.name, &selection.now).await?;
        }
    }
    Ok(())
}

fn ensure_core_resources() -> Result<()> {
    let destination = Config::data_dir().join("Country.mmdb");
    if destination.exists() {
        return Ok(());
    }
    let source = ["/etc/mihomo/Country.mmdb", "/etc/clash/Country.mmdb"]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .context("system Country.mmdb not found; install the Arch clash-geoip package")?;
    link_or_copy(source, &destination).with_context(|| {
        format!(
            "failed to link system Country.mmdb from {} to {}",
            source.display(),
            destination.display()
        )
    })
}

#[cfg(unix)]
fn link_or_copy(source: &Path, destination: &Path) -> Result<()> {
    std::os::unix::fs::symlink(source, destination)
        .or_else(|_| fs::copy(source, destination).map(|_| ()))?;
    Ok(())
}

#[cfg(not(unix))]
fn link_or_copy(source: &Path, destination: &Path) -> Result<()> {
    fs::copy(source, destination)?;
    Ok(())
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SupervisorState {
    pub running: bool,
    pub pid: Option<u32>,
    pub restarts: u64,
    pub reloads: u64,
    pub error: Option<String>,
}

const SUPERVISOR_SERVICE: &str = "omash-supervisor.service";
const PACKAGED_SUPERVISOR_UNIT: &str = "/usr/lib/systemd/user/omash-supervisor.service";

pub async fn ensure_supervisor(auto_start: bool) -> Result<()> {
    let migrated = migrate_legacy_supervisor_unit()?;
    user_systemctl(&["daemon-reload"]).await?;
    if migrated && auto_start {
        user_systemctl(&["reenable", "--now", SUPERVISOR_SERVICE]).await?;
    } else {
        set_supervisor_autostart(auto_start).await?;
    }
    user_systemctl(&["start", SUPERVISOR_SERVICE]).await
}

pub async fn set_supervisor_autostart(enabled: bool) -> Result<()> {
    if enabled {
        user_systemctl(&["enable", "--now", SUPERVISOR_SERVICE]).await
    } else {
        // Disabling login startup must not interrupt the currently running proxy.
        user_systemctl(&["disable", SUPERVISOR_SERVICE]).await
    }
}

fn migrate_legacy_supervisor_unit() -> Result<bool> {
    if !Path::new(PACKAGED_SUPERVISOR_UNIT).is_file() {
        return Ok(false);
    }
    let unit_path = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("systemd/user")
        .join(SUPERVISOR_SERVICE);
    let Some(unit) = fs::read_to_string(&unit_path).ok() else {
        return Ok(false);
    };
    if unit.starts_with("# BinaryModified=") && unit.contains("Description=Omash Mihomo Supervisor")
    {
        fs::remove_file(unit_path)?;
        return Ok(true);
    }
    Ok(false)
}

pub async fn run_supervisor(mut config: Config) -> Result<()> {
    let mut manager = CoreManager::new();
    let mut fingerprint = 0;
    let mut state = SupervisorState::default();
    let mut proxy_applied = false;
    let mut last_start_attempt: Option<Instant> = None;
    loop {
        let enabled = core_desired_enabled();
        let profiles = Profiles::load().unwrap_or_default();
        let current_fingerprint = configuration_fingerprint();
        let restart_requested = Config::restart_request_path().exists();

        if !enabled || profiles.items.is_empty() {
            if proxy_applied {
                let _ = apply_system_proxy(&config, false).await;
                proxy_applied = false;
            }
            if manager.is_running() {
                manager.stop().await?;
            }
            state.running = false;
            state.pid = None;
            state.error = profiles
                .items
                .is_empty()
                .then(|| "Core not started: no profile imported".into());
        } else if !manager.is_running() {
            let retry_due =
                last_start_attempt.is_none_or(|attempt| attempt.elapsed() >= START_RETRY_BACKOFF);
            if retry_due {
                if proxy_applied {
                    let _ = apply_system_proxy(&config, false).await;
                    proxy_applied = false;
                }
                state.running = false;
                state.pid = None;
                state.error = Some(format!("starting {}", profiles.current_core().as_str()));
                write_supervisor_state(&state)?;
                last_start_attempt = Some(Instant::now());
                match manager.start(&config, &profiles).await {
                    Ok(()) => {
                        state.restarts = state.restarts.saturating_add(1);
                        state.error = None;
                        last_start_attempt = None;
                        if config.system_proxy {
                            match apply_system_proxy(&config, true).await {
                                Ok(()) => proxy_applied = true,
                                Err(error) => {
                                    state.error =
                                        Some(format!("core running; system proxy failed: {error}"))
                                }
                            }
                        }
                    }
                    Err(error) => state.error = Some(error.to_string()),
                }
            }
        } else if fingerprint != 0 && (fingerprint != current_fingerprint || restart_requested) {
            if proxy_applied {
                let _ = apply_system_proxy(&config, false).await;
                proxy_applied = false;
            }
            let result = manager.restart(&config, &profiles).await;
            match result {
                Ok(outcome) => {
                    match outcome {
                        ConfigApply::Reloaded => state.reloads = state.reloads.saturating_add(1),
                        ConfigApply::Restarted => state.restarts = state.restarts.saturating_add(1),
                    }
                    state.error = None;
                    if config.system_proxy {
                        match apply_system_proxy(&config, true).await {
                            Ok(()) => proxy_applied = true,
                            Err(error) => {
                                state.error =
                                    Some(format!("core running; system proxy failed: {error}"))
                            }
                        }
                    } else if proxy_applied {
                        let _ = apply_system_proxy(&config, false).await;
                        proxy_applied = false;
                    }
                }
                Err(error) => state.error = Some(error.to_string()),
            }
        }
        if restart_requested {
            let _ = fs::remove_file(Config::restart_request_path());
        }
        state.running = manager.is_running();
        state.pid = manager.pid();
        write_supervisor_state(&state)?;
        fingerprint = current_fingerprint;
        if wait_or_shutdown(Duration::from_secs(1)).await {
            break;
        }
        if let Ok(latest) = load_daemon_config() {
            config = latest;
        }
    }
    if proxy_applied {
        let _ = apply_system_proxy(&config, false).await;
    }
    manager.stop().await?;
    state.running = false;
    state.pid = None;
    write_supervisor_state(&state)?;
    Ok(())
}

pub fn supervisor_state() -> SupervisorState {
    fs::read_to_string(Config::supervisor_state_path())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

pub fn request_core_enabled(enabled: bool) -> Result<()> {
    let path = Config::disabled_state_path();
    if enabled {
        if path.exists() {
            fs::remove_file(path)?;
        }
    } else {
        fs::write(path, b"disabled by user\n")?;
    }
    request_restart()
}

pub fn core_desired_enabled() -> bool {
    !Config::disabled_state_path().exists()
}

pub fn request_restart() -> Result<()> {
    fs::write(
        Config::restart_request_path(),
        format!("{}\n", Local::now().timestamp()),
    )?;
    Ok(())
}

pub async fn cli_stop() -> Result<()> {
    if !core_desired_enabled() && !supervisor_state().running {
        println!("omash core is already stopped");
        return Ok(());
    }
    request_core_enabled(false)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last = supervisor_state();
    while Instant::now() < deadline {
        last = supervisor_state();
        if !last.running {
            println!("omash core stopped; system proxy cleared");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    match last.pid {
        Some(pid) => println!(
            "stop requested, but the core is still running (pid {pid}); see {}",
            Config::logs_dir().display()
        ),
        None => println!(
            "stop requested, but the supervisor did not apply it within 10 seconds; see {}",
            Config::logs_dir().display()
        ),
    }
    Ok(())
}

pub async fn cli_start() -> Result<()> {
    let before = supervisor_state();
    if core_desired_enabled() && before.running {
        println!("omash core is already running");
        return Ok(());
    }
    request_core_enabled(true)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last = before.clone();
    while Instant::now() < deadline {
        last = supervisor_state();
        if last.running {
            match last.pid {
                Some(pid) => println!("omash core started (pid {pid})"),
                None => println!("omash core started"),
            }
            return Ok(());
        }
        if let Some(error) = startup_failure(&before, &last) {
            println!("omash core failed to start: {error}");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    println!(
        "start requested, but the core is not running yet; last state: {}",
        last.error.unwrap_or_else(|| "no response from supervisor".into())
    );
    Ok(())
}

pub async fn cli_restart() -> Result<()> {
    if !core_desired_enabled() {
        println!("omash core is disabled; run `omash start` first");
        return Ok(());
    }
    let before = supervisor_state();
    request_restart()?;
    let applied = before.restarts.saturating_add(before.reloads);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let last = supervisor_state();
        if last.restarts.saturating_add(last.reloads) > applied {
            match last.pid.filter(|_| last.running) {
                Some(pid) => println!("omash core restarted (pid {pid})"),
                None => println!("omash core restarted"),
            }
            return Ok(());
        }
        if let Some(error) = startup_failure(&before, &last) {
            println!("omash core restart failed: {error}");
            return Ok(());
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    println!("restart requested; supervisor did not apply it within 15 seconds");
    Ok(())
}

// The supervisor reports "starting <core>" while a start attempt is in flight;
// only a new, non-transient error compared to the pre-request state means the
// attempt actually failed.
fn startup_failure(before: &SupervisorState, last: &SupervisorState) -> Option<String> {
    let error = last.error.as_ref()?;
    if error.starts_with("starting ") || last.error == before.error {
        return None;
    }
    Some(error.clone())
}

fn load_daemon_config() -> Result<Config> {
    Config::load(&crate::config::Cli {
        command: None,
        daemon: true,
        refresh_ms: None,
        config: None,
    })
}

fn configuration_fingerprint() -> u128 {
    let mut paths = vec![Config::default_path(), Config::profiles_path()];
    if let Ok(entries) = fs::read_dir(Config::profiles_dir()) {
        paths.extend(entries.filter_map(Result::ok).map(|entry| entry.path()));
    }
    paths
        .into_iter()
        .map(|path| modified_nanos(&path))
        .fold(0, u128::wrapping_add)
}

fn modified_nanos(path: &Path) -> u128 {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos())
}

fn write_supervisor_state(state: &SupervisorState) -> Result<()> {
    let path = Config::supervisor_state_path();
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, serde_json::to_vec(state)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}

async fn user_systemctl(arguments: &[&str]) -> Result<()> {
    let output = Command::new("systemctl")
        .arg("--user")
        .args(arguments)
        .output()
        .await?;
    if !output.status.success() {
        bail!(
            "systemctl --user failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(unix)]
async fn wait_or_shutdown(duration: Duration) -> bool {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut terminate) = signal(SignalKind::terminate()) else {
        tokio::time::sleep(duration).await;
        return false;
    };
    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        _ = terminate.recv() => true,
        result = tokio::signal::ctrl_c() => result.is_ok(),
    }
}

#[cfg(not(unix))]
async fn wait_or_shutdown(duration: Duration) -> bool {
    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        result = tokio::signal::ctrl_c() => result.is_ok(),
    }
}

impl Drop for CoreManager {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}

pub async fn apply_system_proxy(config: &Config, enabled: bool) -> Result<()> {
    let mut supported = false;
    if command_exists("gsettings").await {
        supported = true;
        if enabled {
            let port = config.mixed_port.to_string();
            for protocol in ["http", "https", "socks"] {
                let schema = format!("org.gnome.system.proxy.{protocol}");
                run("gsettings", &["set", &schema, "host", "127.0.0.1"]).await?;
                run("gsettings", &["set", &schema, "port", &port]).await?;
            }
            let bypass = gsettings_bypass(&config.proxy_bypass);
            run(
                "gsettings",
                &["set", "org.gnome.system.proxy", "ignore-hosts", &bypass],
            )
            .await?;
            run(
                "gsettings",
                &["set", "org.gnome.system.proxy", "use-same-proxy", "true"],
            )
            .await?;
        }
        run(
            "gsettings",
            &[
                "set",
                "org.gnome.system.proxy.http",
                "enabled",
                if enabled { "true" } else { "false" },
            ],
        )
        .await?;
        let mode = if enabled { "manual" } else { "none" };
        run(
            "gsettings",
            &["set", "org.gnome.system.proxy", "mode", mode],
        )
        .await?;
    }

    // Omarchy launches desktop applications as UWSM/systemd user units. Such
    // applications do not consistently consume GNOME's gsettings proxy, but
    // inherit the user manager environment. Keep both backends in sync.
    if command_exists("systemctl").await {
        supported = true;
        let keys = [
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
        ];
        if enabled {
            let http = format!("http://127.0.0.1:{}", config.mixed_port);
            let socks = format!("socks5://127.0.0.1:{}", config.mixed_port);
            let values = [
                format!("http_proxy={http}"),
                format!("https_proxy={http}"),
                format!("all_proxy={socks}"),
                format!("no_proxy={}", config.proxy_bypass),
                format!("HTTP_PROXY={http}"),
                format!("HTTPS_PROXY={http}"),
                format!("ALL_PROXY={socks}"),
                format!("NO_PROXY={}", config.proxy_bypass),
            ];
            let mut arguments = vec!["--user", "set-environment"];
            arguments.extend(values.iter().map(String::as_str));
            run("systemctl", &arguments).await?;
        } else {
            let mut arguments = vec!["--user", "unset-environment"];
            arguments.extend(keys);
            run("systemctl", &arguments).await?;
        }

        // UWSM scopes inherit the (possibly stale) environment of the menu or
        // compositor that launched them. Services inherit the current systemd
        // user-manager environment, allowing proxy changes to reach Chrome and
        // other newly launched Omarchy applications without a new login.
        if command_exists("uwsm-app").await {
            let unit_type = if enabled { "service" } else { "scope" };
            let setting = format!("UWSM_APP_UNIT_TYPE={unit_type}");
            run("systemctl", &["--user", "set-environment", &setting]).await?;
            let daemon_active = Command::new("systemctl")
                .args([
                    "--user",
                    "is-active",
                    "--quiet",
                    "wayland-wm-app-daemon.service",
                ])
                .status()
                .await
                .is_ok_and(|status| status.success());
            if daemon_active {
                run(
                    "systemctl",
                    &["--user", "restart", "wayland-wm-app-daemon.service"],
                )
                .await?;
            }
        }
    }

    if supported {
        Ok(())
    } else {
        bail!("this session has no supported system-proxy backend")
    }
}

fn gsettings_bypass(value: &str) -> String {
    let items = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| format!("'{}'", item.replace('\\', "\\\\").replace('\'', "\\'")))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{items}]")
}

async fn command_exists(name: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

async fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program).args(args).output().await?;
    if !output.status.success() {
        bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}
