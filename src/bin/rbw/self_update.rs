use std::{
    fmt::Write as _,
    io::{Read as _, Write as _},
    os::unix::fs::PermissionsExt as _,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::Context as _;
use sha2::Digest as _;

const DEFAULT_REPO: &str = "nguyenthdat/rbw";
const DEFAULT_API_BASE: &str = "https://api.github.com";
const MAX_CHECKSUM_BYTES: u64 = 64 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 100 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 100 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

const SUPPORTED_TARGETS: &[&str] = &[
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
];

#[derive(Debug, Clone)]
pub struct UpdateOpts {
    pub check: bool,
    pub version: Option<String>,
    pub force: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum UpdateOutcome {
    Checked {
        current: semver::Version,
        target: semver::Version,
        update_available: bool,
    },
    UpToDate {
        version: semver::Version,
    },
    Updated {
        from: semver::Version,
        to: semver::Version,
        install_dir: PathBuf,
        stopped_agent: bool,
    },
}

#[derive(Debug, Clone)]
struct UpdateConfig {
    repo: String,
    api_base: String,
    allow_http: bool,
    target: String,
    current_version: semver::Version,
    rbw_dest: PathBuf,
    agent_dest: PathBuf,
    github_token: Option<String>,
    stop_running_agent: bool,
}

#[derive(Debug, serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Debug, serde::Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

pub fn run(opts: &UpdateOpts) -> anyhow::Result<()> {
    let cfg = UpdateConfig::from_env()?;
    let outcome = run_with_config(opts, &cfg)?;
    match outcome {
        UpdateOutcome::Checked {
            current,
            target,
            update_available,
        } => {
            if update_available {
                println!(
                    "Update available: rbw v{current} -> v{target}\n\
                     Run `rbw self update` to install."
                );
            } else if target == current {
                println!("rbw is already up to date (v{current}).");
            } else {
                println!(
                    "Current rbw (v{current}) is newer than target release \
                     (v{target})."
                );
            }
        }
        UpdateOutcome::UpToDate { version } => {
            println!("rbw is already up to date (v{version}).");
        }
        UpdateOutcome::Updated {
            from,
            to,
            install_dir,
            stopped_agent,
        } => {
            if stopped_agent {
                eprintln!(
                    "Stopped running rbw-agent (vault locked; run \
                     `rbw unlock` when needed)."
                );
            }
            println!(
                "Updated rbw v{from} -> v{to} in {}",
                install_dir.display()
            );
        }
    }
    Ok(())
}

impl UpdateConfig {
    fn from_env() -> anyhow::Result<Self> {
        let repo = std::env::var("RBW_UPDATE_REPO")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_REPO.to_string());
        validate_repo_slug(&repo)?;

        let api_base = std::env::var("RBW_UPDATE_API_BASE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_API_BASE.to_string());
        let allow_http = is_loopback_http_url(&api_base);
        validate_url(&api_base, allow_http)?;

        let target =
            option_env!("RBW_TARGET").unwrap_or("unknown").to_string();

        let current_version = semver::Version::parse(env!(
            "CARGO_PKG_VERSION"
        ))
        .with_context(|| {
            format!("invalid package version '{}'", env!("CARGO_PKG_VERSION"))
        })?;

        let current_exe = std::env::current_exe()
            .context("failed to determine current rbw executable path")?;
        let rbw_dest =
            std::fs::canonicalize(&current_exe).unwrap_or(current_exe);
        let install_dir = rbw_dest.parent().with_context(|| {
            format!(
                "executable '{}' has no parent directory",
                rbw_dest.display()
            )
        })?;
        let agent_dest = install_dir.join("rbw-agent");

        let github_token = std::env::var("GITHUB_TOKEN")
            .or_else(|_| std::env::var("GH_TOKEN"))
            .ok()
            .filter(|s| !s.trim().is_empty());

        Ok(Self {
            repo,
            api_base: api_base.trim_end_matches('/').to_string(),
            allow_http,
            target,
            current_version,
            rbw_dest,
            agent_dest,
            github_token,
            stop_running_agent: true,
        })
    }
}

fn run_with_config(
    opts: &UpdateOpts,
    cfg: &UpdateConfig,
) -> anyhow::Result<UpdateOutcome> {
    if !SUPPORTED_TARGETS.contains(&cfg.target.as_str()) {
        anyhow::bail!(
            "no prebuilt release binaries are published for target '{}'; \
             install from source with `cargo install --locked rbw`",
            cfg.target
        );
    }

    if !opts.check
        && !opts.force
        && let Some(pm) = detect_package_manager(&cfg.rbw_dest)
    {
        anyhow::bail!(
            "rbw at '{}' appears to be managed by {pm}; \
             upgrade it via {pm} or re-run with --force",
            cfg.rbw_dest.display()
        );
    }

    let api_client = build_http_client(cfg.allow_http)?;
    let download_client = build_http_client(cfg.allow_http)?;

    let release = fetch_release(&api_client, cfg, opts.version.as_deref())?;
    let target_version = parse_release_version(&release.tag_name)?;

    if opts.check {
        return Ok(UpdateOutcome::Checked {
            update_available: target_version > cfg.current_version,
            current: cfg.current_version.clone(),
            target: target_version,
        });
    }

    if !opts.force {
        if target_version == cfg.current_version {
            return Ok(UpdateOutcome::UpToDate {
                version: cfg.current_version.clone(),
            });
        }
        if target_version < cfg.current_version && opts.version.is_none() {
            eprintln!(
                "Current rbw (v{}) is newer than latest release (v{}); \
                 pass --force to reinstall.",
                cfg.current_version, target_version
            );
            return Ok(UpdateOutcome::UpToDate {
                version: cfg.current_version.clone(),
            });
        }
    }

    let archive_name = format!("rbw-{}.tar.gz", cfg.target);
    let archive_asset = release
        .assets
        .iter()
        .find(|a| a.name == archive_name)
        .with_context(|| {
            format!(
                "release '{}' does not contain asset '{archive_name}'",
                release.tag_name
            )
        })?;
    let checksum_asset = release
        .assets
        .iter()
        .find(|a| a.name == format!("{archive_name}.sha256"))
        .or_else(|| release.assets.iter().find(|a| a.name == "SHA256SUMS"))
        .with_context(|| {
            format!(
                "release '{}' is missing SHA-256 checksum asset for \
                 '{archive_name}'",
                release.tag_name
            )
        })?;

    validate_url(&archive_asset.browser_download_url, cfg.allow_http)?;
    validate_url(&checksum_asset.browser_download_url, cfg.allow_http)?;

    let install_dir = cfg
        .rbw_dest
        .parent()
        .context("target rbw executable has no parent directory")?
        .to_path_buf();
    let agent_dir = cfg
        .agent_dest
        .parent()
        .context("target rbw-agent executable has no parent directory")?
        .to_path_buf();

    // Fail fast on directory permission errors before downloading or stopping
    // a running rbw-agent.
    verify_dir_writable(&install_dir)?;
    if agent_dir != install_dir {
        verify_dir_writable(&agent_dir)?;
    }

    let checksum_text = download_text(
        &download_client,
        &checksum_asset.browser_download_url,
        MAX_CHECKSUM_BYTES,
    )
    .with_context(|| {
        format!("failed to download checksum '{}'", checksum_asset.name)
    })?;
    let expected_sha256 =
        parse_sha256_for_asset(&checksum_text, &archive_name)?;

    let stage_dir = tempfile::tempdir()
        .context("failed to create temporary staging directory")?;
    let archive_path = stage_dir.path().join(&archive_name);

    eprintln!("Downloading {archive_name} ({})...", release.tag_name);
    let actual_sha256 = download_file_and_sha256(
        &download_client,
        &archive_asset.browser_download_url,
        &archive_path,
        MAX_ARCHIVE_BYTES,
    )
    .with_context(|| format!("failed to download '{archive_name}'"))?;

    if actual_sha256 != expected_sha256 {
        anyhow::bail!(
            "SHA-256 checksum mismatch for '{archive_name}': \
             expected {expected_sha256}, got {actual_sha256}"
        );
    }

    let (staged_rbw, staged_agent) =
        extract_release_binaries(&archive_path, stage_dir.path())?;

    verify_staged_binary(&staged_rbw, &target_version)?;

    let (tmp_rbw, tmp_agent) = stage_binaries_in_dest(
        &staged_rbw,
        &staged_agent,
        &install_dir,
        &agent_dir,
    )?;

    let stopped_agent = cfg.stop_running_agent && stop_agent_if_running()?;

    install_staged_binaries(
        tmp_rbw,
        tmp_agent,
        &cfg.rbw_dest,
        &cfg.agent_dest,
    )?;

    if !release.html_url.is_empty() {
        log::debug!("installed release from {}", release.html_url);
    }

    Ok(UpdateOutcome::Updated {
        from: cfg.current_version.clone(),
        to: target_version,
        install_dir,
        stopped_agent,
    })
}

fn build_http_client(
    allow_http: bool,
) -> anyhow::Result<reqwest::blocking::Client> {
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 10 {
            return attempt.error("too many HTTP redirects");
        }
        let url = attempt.url();
        let scheme_ok = url.scheme() == "https"
            || (allow_http && is_loopback_http_url(url.as_str()));
        if !scheme_ok {
            return attempt
                .error("refusing insecure redirect to non-HTTPS URL");
        }
        attempt.follow()
    });

    reqwest::blocking::Client::builder()
        .user_agent(format!("rbw/{}", env!("CARGO_PKG_VERSION")))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(policy)
        .build()
        .context("failed to build HTTP client")
}

fn fetch_release(
    client: &reqwest::blocking::Client,
    cfg: &UpdateConfig,
    requested_version: Option<&str>,
) -> anyhow::Result<GithubRelease> {
    let Some(raw_ver) = requested_version else {
        let url =
            format!("{}/repos/{}/releases/latest", cfg.api_base, cfg.repo);
        return fetch_release_at_url(
            client,
            &url,
            cfg.github_token.as_deref(),
        )?
        .with_context(|| {
            format!("no published GitHub release found for '{}'", cfg.repo)
        });
    };

    let normalized = normalize_requested_version(raw_ver)?;
    let v_tag = format!("v{normalized}");
    let url_with_v =
        format!("{}/repos/{}/releases/tags/{v_tag}", cfg.api_base, cfg.repo);
    if let Some(release) = fetch_release_at_url(
        client,
        &url_with_v,
        cfg.github_token.as_deref(),
    )? {
        return Ok(release);
    }

    let url_bare = format!(
        "{}/repos/{}/releases/tags/{normalized}",
        cfg.api_base, cfg.repo
    );
    fetch_release_at_url(client, &url_bare, cfg.github_token.as_deref())?
        .with_context(|| {
            format!("release '{v_tag}' not found in '{}'", cfg.repo)
        })
}

fn fetch_release_at_url(
    client: &reqwest::blocking::Client,
    url: &str,
    github_token: Option<&str>,
) -> anyhow::Result<Option<GithubRelease>> {
    let mut req = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if let Some(token) = github_token {
        req = req.bearer_auth(token);
    }

    let res = req
        .send()
        .with_context(|| format!("failed to query release API at {url}"))?;
    let status = res.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if status == reqwest::StatusCode::FORBIDDEN
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
    {
        anyhow::bail!(
            "GitHub API rate limit exceeded ({status}); set GITHUB_TOKEN \
             and retry"
        );
    }
    if !status.is_success() {
        anyhow::bail!(
            "GitHub API request to {url} failed with status {status}"
        );
    }

    let release = res
        .json::<GithubRelease>()
        .context("failed to parse GitHub release metadata")?;
    Ok(Some(release))
}

fn download_text(
    client: &reqwest::blocking::Client,
    url: &str,
    max_bytes: u64,
) -> anyhow::Result<String> {
    let res = client
        .get(url)
        .send()
        .with_context(|| format!("HTTP GET {url} failed"))?;
    let status = res.status();
    if !status.is_success() {
        anyhow::bail!("download from {url} failed with status {status}");
    }

    let mut limited = res.take(max_bytes + 1);
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .context("failed to read response body")?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max_bytes {
        anyhow::bail!("response from {url} exceeded {max_bytes} byte limit");
    }
    String::from_utf8(buf).context("checksum file is not valid UTF-8")
}

fn download_file_and_sha256(
    client: &reqwest::blocking::Client,
    url: &str,
    dest: &Path,
    max_bytes: u64,
) -> anyhow::Result<String> {
    let mut res = client
        .get(url)
        .send()
        .with_context(|| format!("HTTP GET {url} failed"))?;
    let status = res.status();
    if !status.is_success() {
        anyhow::bail!("download from {url} failed with status {status}");
    }
    if let Some(len) = res.content_length()
        && len > max_bytes
    {
        anyhow::bail!(
            "archive size ({len} bytes) exceeds {max_bytes} byte limit"
        );
    }

    let mut file = std::fs::File::create(dest).with_context(|| {
        format!("failed to create temp archive '{}'", dest.display())
    })?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0_u8; 64 * 1024];
    let mut total: u64 = 0;

    loop {
        let n = res
            .read(&mut buf)
            .context("failed while downloading archive")?;
        if n == 0 {
            break;
        }
        let n_u64 = u64::try_from(n).context("chunk length overflow")?;
        total = total.saturating_add(n_u64);
        if total > max_bytes {
            anyhow::bail!(
                "downloaded archive exceeded {max_bytes} byte limit"
            );
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])
            .context("failed writing downloaded archive")?;
    }
    file.flush().context("failed flushing downloaded archive")?;

    Ok(encode_hex_lower(&hasher.finalize()))
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn parse_sha256_for_asset(
    content: &str,
    asset_name: &str,
) -> anyhow::Result<String> {
    let lines: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    if lines.is_empty() {
        anyhow::bail!("checksum file is empty");
    }

    for line in &lines {
        let mut parts = line.split_whitespace();
        let Some(hash) = parts.next() else {
            continue;
        };
        match parts.next() {
            Some(file_part) => {
                let normalized = file_part
                    .trim_start_matches('*')
                    .trim_start_matches("./");
                let matches_asset = normalized == asset_name
                    || Path::new(normalized)
                        .file_name()
                        .is_some_and(|name| name == asset_name);
                if matches_asset {
                    return validate_sha256_hex(hash);
                }
            }
            None if lines.len() == 1 => {
                return validate_sha256_hex(hash);
            }
            None => {}
        }
    }

    anyhow::bail!("no SHA-256 entry found for '{asset_name}'")
}

fn validate_sha256_hex(hash: &str) -> anyhow::Result<String> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("invalid SHA-256 digest '{hash}'");
    }
    Ok(hash.to_ascii_lowercase())
}

fn extract_release_binaries(
    archive_path: &Path,
    stage_dir: &Path,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    let file = std::fs::File::open(archive_path).with_context(|| {
        format!("failed to open archive '{}'", archive_path.display())
    })?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);

    let rbw_out = stage_dir.join("rbw");
    let agent_out = stage_dir.join("rbw-agent");
    let mut found_rbw = false;
    let mut found_agent = false;

    for entry in archive
        .entries()
        .context("failed to read release tar.gz entries")?
    {
        let entry = entry.context("failed to read tar entry")?;
        let entry_path = entry
            .path()
            .context("invalid path in release archive")?
            .into_owned();
        let target_bin = classify_archive_binary(&entry_path)?;
        let Some(bin_name) = target_bin else {
            continue;
        };

        let entry_type = entry.header().entry_type();
        if !entry_type.is_file() {
            anyhow::bail!(
                "refusing non-regular archive entry '{}' ({entry_type:?})",
                entry_path.display()
            );
        }

        if entry.size() > MAX_BINARY_BYTES {
            anyhow::bail!(
                "archive entry '{}' exceeds {MAX_BINARY_BYTES} byte limit",
                entry_path.display()
            );
        }

        let (dest, seen) = match bin_name {
            "rbw" => (&rbw_out, &mut found_rbw),
            "rbw-agent" => (&agent_out, &mut found_agent),
            _ => unreachable!(),
        };
        if *seen {
            anyhow::bail!(
                "duplicate '{bin_name}' binary found in release archive"
            );
        }

        let mut out_file =
            std::fs::File::create(dest).with_context(|| {
                format!("failed to create staged binary '{}'", dest.display())
            })?;
        let mut limited = entry.take(MAX_BINARY_BYTES + 1);
        let written = std::io::copy(&mut limited, &mut out_file)
            .with_context(|| format!("failed to extract '{bin_name}'"))?;
        if written == 0 {
            anyhow::bail!("extracted '{bin_name}' binary is empty");
        }
        if written > MAX_BINARY_BYTES {
            anyhow::bail!(
                "extracted '{bin_name}' binary exceeded {MAX_BINARY_BYTES} \
                 byte limit"
            );
        }
        out_file.sync_all().with_context(|| {
            format!("failed to flush staged binary '{}'", dest.display())
        })?;
        std::fs::set_permissions(
            dest,
            std::fs::Permissions::from_mode(0o755),
        )
        .with_context(|| {
            format!(
                "failed to set executable permissions on '{}'",
                dest.display()
            )
        })?;
        *seen = true;
    }

    if !found_rbw {
        anyhow::bail!("release archive is missing 'rbw' binary");
    }
    if !found_agent {
        anyhow::bail!("release archive is missing 'rbw-agent' binary");
    }

    Ok((rbw_out, agent_out))
}

fn classify_archive_binary(
    path: &Path,
) -> anyhow::Result<Option<&'static str>> {
    let mut parts = Vec::new();
    for comp in path.components() {
        match comp {
            Component::Normal(seg) => parts.push(seg),
            Component::CurDir => {}
            Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                anyhow::bail!(
                    "refusing unsafe path '{}' in release archive",
                    path.display()
                );
            }
        }
    }

    let name = match parts.as_slice() {
        [file] | [_, file] => file.to_str(),
        _ => return Ok(None),
    };

    match name {
        Some("rbw") => Ok(Some("rbw")),
        Some("rbw-agent") => Ok(Some("rbw-agent")),
        _ => Ok(None),
    }
}

fn verify_staged_binary(
    staged_rbw: &Path,
    expected_version: &semver::Version,
) -> anyhow::Result<()> {
    let output = std::process::Command::new(staged_rbw)
        .arg("--version")
        .output()
        .with_context(|| {
            format!(
                "failed to execute downloaded binary '{}' for pre-flight check",
                staged_rbw.display()
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "downloaded rbw binary failed pre-flight `--version` check ({}): \
             {}",
            output.status,
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = expected_version.to_string();
    if !stdout.contains(&expected) {
        anyhow::bail!(
            "downloaded binary reported unexpected version '{}' \
             (expected '{expected}')",
            stdout.trim()
        );
    }
    Ok(())
}

fn verify_dir_writable(dir: &Path) -> anyhow::Result<()> {
    let probe = tempfile::NamedTempFile::new_in(dir).with_context(|| {
        format!(
            "cannot write to install directory '{}'; check permissions or \
             reinstall in a user-writable directory",
            dir.display()
        )
    })?;
    drop(probe);
    Ok(())
}

fn stage_binaries_in_dest(
    staged_rbw: &Path,
    staged_agent: &Path,
    install_dir: &Path,
    agent_dir: &Path,
) -> anyhow::Result<(tempfile::NamedTempFile, tempfile::NamedTempFile)> {
    let tmp_rbw = copy_to_temp_executable(staged_rbw, install_dir)?;
    let tmp_agent = copy_to_temp_executable(staged_agent, agent_dir)?;
    Ok((tmp_rbw, tmp_agent))
}

fn copy_to_temp_executable(
    src: &Path,
    dest_dir: &Path,
) -> anyhow::Result<tempfile::NamedTempFile> {
    let mut reader = std::fs::File::open(src).with_context(|| {
        format!("failed to open staged binary '{}'", src.display())
    })?;
    let mut tmp =
        tempfile::NamedTempFile::new_in(dest_dir).with_context(|| {
            format!("failed to create temp file in '{}'", dest_dir.display())
        })?;
    std::io::copy(&mut reader, &mut tmp).with_context(|| {
        format!("failed to stage binary into '{}'", dest_dir.display())
    })?;
    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o755))
        .context("failed to set executable permissions on staged binary")?;
    tmp.as_file()
        .sync_all()
        .context("failed to sync staged binary to disk")?;
    Ok(tmp)
}

fn stop_agent_if_running() -> anyhow::Result<bool> {
    if crate::sock::Sock::connect().is_err() {
        return Ok(false);
    }
    crate::commands::stop_agent()
        .context("failed to stop running rbw-agent before update")?;
    Ok(true)
}

fn install_staged_binaries(
    tmp_rbw: tempfile::NamedTempFile,
    tmp_agent: tempfile::NamedTempFile,
    rbw_dest: &Path,
    agent_dest: &Path,
) -> anyhow::Result<()> {
    let agent_backup = if agent_dest.exists() {
        let backup_dir = agent_dest
            .parent()
            .context("rbw-agent destination has no parent directory")?;
        Some(copy_to_temp_executable(agent_dest, backup_dir)?)
    } else {
        None
    };

    tmp_agent
        .persist(agent_dest)
        .map_err(|e| e.error)
        .with_context(|| {
            format!(
                "failed to replace rbw-agent at '{}'",
                agent_dest.display()
            )
        })?;

    if let Err(err) = tmp_rbw.persist(rbw_dest) {
        if let Some(backup) = agent_backup {
            let _ = backup.persist(agent_dest);
        }
        return Err(err.error).with_context(|| {
            format!("failed to replace rbw at '{}'", rbw_dest.display())
        });
    }

    drop(agent_backup);
    Ok(())
}

fn detect_package_manager(exe_path: &Path) -> Option<&'static str> {
    let path_str = exe_path.to_string_lossy();
    if path_str.contains("/Cellar/") || path_str.contains("/homebrew/") {
        return Some("Homebrew (`brew upgrade rbw`)");
    }
    if path_str.starts_with("/nix/store/") {
        return Some("Nix");
    }
    if path_str.starts_with("/snap/") {
        return Some("Snap");
    }
    if path_str.starts_with("/usr/bin/") {
        return Some("your system package manager");
    }
    None
}

fn normalize_requested_version(raw: &str) -> anyhow::Result<semver::Version> {
    let trimmed = raw.trim().trim_start_matches('v');
    semver::Version::parse(trimmed).with_context(|| {
        format!(
            "invalid version '{raw}'; expected semantic version like \
             '1.16.0' or 'v1.16.0'"
        )
    })
}

fn parse_release_version(tag: &str) -> anyhow::Result<semver::Version> {
    let trimmed = tag.trim().trim_start_matches('v');
    semver::Version::parse(trimmed)
        .with_context(|| format!("release tag '{tag}' is not valid semver"))
}

fn validate_repo_slug(repo: &str) -> anyhow::Result<()> {
    let Some((owner, name)) = repo.split_once('/') else {
        anyhow::bail!(
            "invalid repository '{repo}'; expected '<owner>/<repo>'"
        );
    };
    let valid_part = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
            })
    };
    if !valid_part(owner) || !valid_part(name) || name.contains('/') {
        anyhow::bail!(
            "invalid repository '{repo}'; expected '<owner>/<repo>'"
        );
    }
    Ok(())
}

fn is_loopback_http_url(raw: &str) -> bool {
    url::Url::parse(raw).is_ok_and(|u| {
        u.scheme() == "http"
            && matches!(
                u.host_str(),
                Some("127.0.0.1" | "localhost" | "[::1]")
            )
    })
}

fn validate_url(raw: &str, allow_http: bool) -> anyhow::Result<()> {
    let parsed = url::Url::parse(raw)
        .with_context(|| format!("invalid URL '{raw}'"))?;
    let scheme_ok = parsed.scheme() == "https"
        || (allow_http && is_loopback_http_url(raw));
    if !scheme_ok {
        anyhow::bail!("refusing non-HTTPS URL '{raw}'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        );
        {
            let mut builder = tar::Builder::new(&mut encoder);
            for (name, content) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(u64::try_from(content.len()).unwrap());
                header.set_mode(0o755);
                header.set_cksum();
                builder.append_data(&mut header, *name, *content).unwrap();
            }
            builder.finish().unwrap();
        }
        encoder.finish().unwrap()
    }

    #[test]
    fn test_parse_sha256_formats() {
        let valid_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let upper_hash = valid_hash.to_ascii_uppercase();

        assert_eq!(
            parse_sha256_for_asset(
                &format!("{upper_hash}  rbw-aarch64-apple-darwin.tar.gz\n"),
                "rbw-aarch64-apple-darwin.tar.gz",
            )
            .unwrap(),
            valid_hash
        );

        assert_eq!(
            parse_sha256_for_asset(
                &format!("{valid_hash}\n"),
                "rbw-aarch64-apple-darwin.tar.gz",
            )
            .unwrap(),
            valid_hash
        );

        let sums = format!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  other.tar.gz\n\
             {valid_hash}  *./rbw-x86_64-unknown-linux-musl.tar.gz\n"
        );
        assert_eq!(
            parse_sha256_for_asset(
                &sums,
                "rbw-x86_64-unknown-linux-musl.tar.gz"
            )
            .unwrap(),
            valid_hash
        );

        assert!(parse_sha256_for_asset(&sums, "rbw-missing.tar.gz").is_err());
        assert!(
            parse_sha256_for_asset("not-a-hash  rbw.tar.gz", "rbw.tar.gz")
                .is_err()
        );
    }

    #[test]
    fn test_version_and_repo_validation() {
        assert_eq!(
            normalize_requested_version("v1.16.0").unwrap(),
            semver::Version::new(1, 16, 0)
        );
        assert_eq!(
            normalize_requested_version("1.16.0-rc.1").unwrap(),
            semver::Version::parse("1.16.0-rc.1").unwrap()
        );
        assert!(normalize_requested_version("../etc/passwd").is_err());

        assert!(validate_repo_slug("nguyenthdat/rbw").is_ok());
        assert!(validate_repo_slug("bad").is_err());
        assert!(validate_repo_slug("a/b/c").is_err());
        assert!(validate_repo_slug("../evil").is_err());
    }

    #[test]
    fn test_detect_package_manager() {
        assert!(
            detect_package_manager(Path::new(
                "/opt/homebrew/Cellar/rbw/1.15.0/bin/rbw"
            ))
            .is_some()
        );
        assert!(detect_package_manager(Path::new("/usr/bin/rbw")).is_some());
        assert!(
            detect_package_manager(Path::new(
                "/nix/store/abc-rbw-1.15.0/bin/rbw"
            ))
            .is_some()
        );
        assert!(
            detect_package_manager(Path::new("/Users/alice/.local/bin/rbw"))
                .is_none()
        );
    }

    #[test]
    fn test_extract_release_binaries_and_security_checks() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("ok.tar.gz");
        let bytes = build_test_tar_gz(&[
            (
                "rbw-aarch64-apple-darwin/rbw",
                b"#!/bin/sh\necho rbw 1.16.0\n",
            ),
            ("rbw-aarch64-apple-darwin/rbw-agent", b"agent-binary"),
            ("rbw-aarch64-apple-darwin/README.md", b"readme"),
        ]);
        std::fs::write(&archive_path, bytes).unwrap();

        let extract_dir = tempfile::tempdir().unwrap();
        let (rbw, agent) =
            extract_release_binaries(&archive_path, extract_dir.path())
                .unwrap();
        assert_eq!(
            std::fs::read(&rbw).unwrap(),
            b"#!/bin/sh\necho rbw 1.16.0\n"
        );
        assert_eq!(std::fs::read(&agent).unwrap(), b"agent-binary");
        assert_eq!(
            std::fs::metadata(&rbw).unwrap().permissions().mode() & 0o777,
            0o755
        );

        // Missing rbw-agent should fail.
        let missing_path = dir.path().join("missing.tar.gz");
        std::fs::write(
            &missing_path,
            build_test_tar_gz(&[("rbw-aarch64-apple-darwin/rbw", b"only")]),
        )
        .unwrap();
        assert!(
            extract_release_binaries(
                &missing_path,
                tempfile::tempdir().unwrap().path()
            )
            .is_err()
        );

        // Path traversal must be rejected.
        assert!(classify_archive_binary(Path::new("../rbw")).is_err());
        assert!(classify_archive_binary(Path::new("/etc/rbw")).is_err());
        assert_eq!(
            classify_archive_binary(Path::new("a/b/rbw")).unwrap(),
            None
        );

        // Symlink entry named rbw must be rejected.
        let symlink_path = dir.path().join("symlink.tar.gz");
        let mut encoder = flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        );
        {
            let mut builder = tar::Builder::new(&mut encoder);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_cksum();
            builder
                .append_link(
                    &mut header,
                    "rbw-aarch64-apple-darwin/rbw",
                    "/bin/sh",
                )
                .unwrap();
            builder.finish().unwrap();
        }
        std::fs::write(&symlink_path, encoder.finish().unwrap()).unwrap();
        assert!(
            extract_release_binaries(
                &symlink_path,
                tempfile::tempdir().unwrap().path()
            )
            .is_err()
        );
    }

    #[test]
    fn test_end_to_end_self_update_against_local_mock_server() {
        let target = "aarch64-apple-darwin";
        let archive_name = format!("rbw-{target}.tar.gz");
        let new_rbw = b"#!/bin/sh\necho \"rbw 9.9.9\"\n";
        let new_agent = b"#!/bin/sh\necho \"rbw-agent 9.9.9\"\n";
        let archive_bytes = build_test_tar_gz(&[
            (&format!("rbw-{target}/rbw"), new_rbw),
            (&format!("rbw-{target}/rbw-agent"), new_agent),
        ]);
        let sha256 = encode_hex_lower(&sha2::Sha256::digest(&archive_bytes));
        let sha_body = format!("{sha256}  {archive_name}\n");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let release_json = serde_json::json!({
            "tag_name": "v9.9.9",
            "html_url": format!("{base_url}/releases/tag/v9.9.9"),
            "assets": [
                {
                    "name": archive_name,
                    "browser_download_url": format!("{base_url}/download/{archive_name}")
                },
                {
                    "name": format!("{archive_name}.sha256"),
                    "browser_download_url": format!("{base_url}/download/{archive_name}.sha256")
                }
            ]
        })
        .to_string();

        let archive_for_server = archive_bytes;
        let sha_for_server = sha_body;
        let handle = std::thread::spawn(move || {
            for _ in 0..6 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut req_buf = [0_u8; 4096];
                let n = stream.read(&mut req_buf).unwrap_or(0);
                let req_str = String::from_utf8_lossy(&req_buf[..n]);
                let path = req_str
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");

                let (status, content_type, body): (&str, &str, Vec<u8>) =
                    if path == "/repos/nguyenthdat/rbw/releases/latest"
                        || path
                            == "/repos/nguyenthdat/rbw/releases/tags/v9.9.9"
                    {
                        (
                            "200 OK",
                            "application/json",
                            release_json.as_bytes().to_vec(),
                        )
                    } else if path == format!("/download/{archive_name}") {
                        (
                            "200 OK",
                            "application/octet-stream",
                            archive_for_server.clone(),
                        )
                    } else if path
                        == format!("/download/{archive_name}.sha256")
                    {
                        (
                            "200 OK",
                            "text/plain",
                            sha_for_server.as_bytes().to_vec(),
                        )
                    } else {
                        ("404 Not Found", "text/plain", b"not found".to_vec())
                    };

                let header = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });

        let install_dir = tempfile::tempdir().unwrap();
        let rbw_dest = install_dir.path().join("rbw");
        let agent_dest = install_dir.path().join("rbw-agent");
        std::fs::write(&rbw_dest, b"old-rbw").unwrap();
        std::fs::write(&agent_dest, b"old-agent").unwrap();

        let cfg = UpdateConfig {
            repo: DEFAULT_REPO.to_string(),
            api_base: base_url,
            allow_http: true,
            target: target.to_string(),
            current_version: semver::Version::new(1, 15, 0),
            rbw_dest: rbw_dest.clone(),
            agent_dest: agent_dest.clone(),
            github_token: None,
            stop_running_agent: false,
        };

        // 1. --check only checks and does not overwrite files.
        let check_res = run_with_config(
            &UpdateOpts {
                check: true,
                version: None,
                force: false,
            },
            &cfg,
        )
        .unwrap();
        assert_eq!(
            check_res,
            UpdateOutcome::Checked {
                current: semver::Version::new(1, 15, 0),
                target: semver::Version::new(9, 9, 9),
                update_available: true,
            }
        );
        assert_eq!(std::fs::read(&rbw_dest).unwrap(), b"old-rbw");

        // 2. Real update downloads, verifies SHA-256, smoke-tests, and swaps.
        let update_res = run_with_config(
            &UpdateOpts {
                check: false,
                version: None,
                force: false,
            },
            &cfg,
        )
        .unwrap();
        assert_eq!(
            update_res,
            UpdateOutcome::Updated {
                from: semver::Version::new(1, 15, 0),
                to: semver::Version::new(9, 9, 9),
                install_dir: install_dir.path().to_path_buf(),
                stopped_agent: false,
            }
        );
        assert_eq!(std::fs::read(&rbw_dest).unwrap(), new_rbw);
        assert_eq!(std::fs::read(&agent_dest).unwrap(), new_agent);

        // 3. Re-running at v9.9.9 without --force reports up-to-date.
        let mut already_cfg = cfg;
        already_cfg.current_version = semver::Version::new(9, 9, 9);
        let noop_res = run_with_config(
            &UpdateOpts {
                check: false,
                version: Some("9.9.9".to_string()),
                force: false,
            },
            &already_cfg,
        )
        .unwrap();
        assert_eq!(
            noop_res,
            UpdateOutcome::UpToDate {
                version: semver::Version::new(9, 9, 9),
            }
        );

        // Wake the mock listener if it is still waiting for remaining slots.
        let _ = std::net::TcpStream::connect(addr);
        let _ = handle.join();
    }
}
