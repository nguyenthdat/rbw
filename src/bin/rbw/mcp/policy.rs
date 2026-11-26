use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context as _;

#[derive(Debug, Clone)]
pub struct McpPolicy {
    pub default_account: Option<String>,
    pub allow_write: bool,
    pub allowed_dirs: Vec<PathBuf>,
    pub unlock_timeout: Duration,
}

impl McpPolicy {
    pub fn new(
        default_account: Option<String>,
        allow_write: bool,
        raw_allowed_dirs: &[PathBuf],
        unlock_timeout_secs: u64,
    ) -> anyhow::Result<Self> {
        if unlock_timeout_secs == 0 {
            anyhow::bail!("--unlock-timeout must be at least 1 second");
        }

        let mut allowed_dirs = Vec::with_capacity(raw_allowed_dirs.len());
        for raw in raw_allowed_dirs {
            if raw.as_os_str().is_empty() {
                continue;
            }
            let canonical = std::fs::canonicalize(raw).with_context(|| {
                format!(
                    "allowed directory '{}' does not exist or cannot be accessed",
                    raw.display()
                )
            })?;
            if !canonical.is_dir() {
                anyhow::bail!(
                    "allowed path '{}' is not a directory",
                    raw.display()
                );
            }
            if !allowed_dirs.contains(&canonical) {
                allowed_dirs.push(canonical);
            }
        }

        let default_account = default_account
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        Ok(Self {
            default_account,
            allow_write,
            allowed_dirs,
            unlock_timeout: Duration::from_secs(unlock_timeout_secs),
        })
    }

    pub fn resolve_account<'a>(
        &'a self,
        override_account: Option<&'a str>,
    ) -> Option<&'a str> {
        override_account
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or(self.default_account.as_deref())
    }

    pub fn validate_upload_path(
        &self,
        raw: &Path,
    ) -> anyhow::Result<PathBuf> {
        if self.allowed_dirs.is_empty() {
            anyhow::bail!(
                "attachment file operations are disabled; pass --allowed-dir <DIR> or set RBW_MCP_ALLOWED_DIRS"
            );
        }
        if raw.as_os_str().is_empty() || raw == Path::new("-") {
            anyhow::bail!("attachment path must be a regular file path");
        }
        let canonical = std::fs::canonicalize(raw).with_context(|| {
            format!("attachment source '{}' does not exist", raw.display())
        })?;
        if !canonical.is_file() {
            anyhow::bail!(
                "attachment source '{}' is not a regular file",
                raw.display()
            );
        }
        if !self.is_within_allowed_dirs(&canonical) {
            anyhow::bail!(
                "path '{}' is outside allowed directories",
                raw.display()
            );
        }
        Ok(canonical)
    }

    pub fn validate_download_path(
        &self,
        raw: &Path,
    ) -> anyhow::Result<PathBuf> {
        if self.allowed_dirs.is_empty() {
            anyhow::bail!(
                "attachment file operations are disabled; pass --allowed-dir <DIR> or set RBW_MCP_ALLOWED_DIRS"
            );
        }
        if raw.as_os_str().is_empty() || raw == Path::new("-") {
            anyhow::bail!(
                "attachment output path must be a regular file path"
            );
        }
        let Some(file_name) = raw.file_name() else {
            anyhow::bail!(
                "attachment output path '{}' must include a filename",
                raw.display()
            );
        };
        if file_name == "." || file_name == ".." {
            anyhow::bail!(
                "attachment output path '{}' has an invalid filename",
                raw.display()
            );
        }
        let parent = raw
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "attachment output path '{}' must include an allowed parent directory",
                    raw.display()
                )
            })?;
        let canonical_parent =
            std::fs::canonicalize(parent).with_context(|| {
                format!(
                    "attachment destination directory '{}' does not exist",
                    parent.display()
                )
            })?;
        if !canonical_parent.is_dir() {
            anyhow::bail!(
                "attachment destination parent '{}' is not a directory",
                parent.display()
            );
        }
        if !self.is_within_allowed_dirs(&canonical_parent) {
            anyhow::bail!(
                "path '{}' is outside allowed directories",
                raw.display()
            );
        }
        let target = canonical_parent.join(file_name);
        if std::fs::symlink_metadata(&target).is_ok() {
            anyhow::bail!(
                "attachment output '{}' already exists (refusing to overwrite)",
                target.display()
            );
        }
        Ok(target)
    }

    fn is_within_allowed_dirs(&self, canonical_path: &Path) -> bool {
        self.allowed_dirs
            .iter()
            .any(|allowed| canonical_path.starts_with(allowed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_rejects_invalid_allowed_dirs_and_zero_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();

        assert!(McpPolicy::new(None, false, &[], 0).is_err());
        assert!(McpPolicy::new(None, false, &[file], 60).is_err());
        assert!(
            McpPolicy::new(None, false, &[dir.path().join("missing")], 60)
                .is_err()
        );
    }

    #[test]
    fn test_policy_upload_path_enforces_allowlist_and_blocks_symlink_escape()
    {
        let allowed = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        let good = allowed.path().join("ok.txt");
        std::fs::write(&good, b"hello").unwrap();

        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, b"nope").unwrap();

        let escape_link = allowed.path().join("escape.txt");
        std::os::unix::fs::symlink(&secret, &escape_link).unwrap();

        let policy =
            McpPolicy::new(None, true, &[allowed.path().to_path_buf()], 60)
                .unwrap();

        let resolved = policy.validate_upload_path(&good).unwrap();
        assert_eq!(resolved, std::fs::canonicalize(&good).unwrap());

        assert!(policy.validate_upload_path(&secret).is_err());
        assert!(policy.validate_upload_path(&escape_link).is_err());
        assert!(policy.validate_upload_path(allowed.path()).is_err());
        assert!(policy.validate_upload_path(Path::new("-")).is_err());

        let traversal = allowed
            .path()
            .join("..")
            .join(outside.path().file_name().unwrap())
            .join("secret.txt");
        assert!(policy.validate_upload_path(&traversal).is_err());
    }

    #[test]
    fn test_policy_download_path_enforces_allowlist_and_noclobber() {
        let allowed = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        let existing = allowed.path().join("existing.bin");
        std::fs::write(&existing, b"keep").unwrap();

        let symlink_dir = allowed.path().join("outlink");
        std::os::unix::fs::symlink(outside.path(), &symlink_dir).unwrap();

        let policy =
            McpPolicy::new(None, false, &[allowed.path().to_path_buf()], 60)
                .unwrap();

        let fresh = allowed.path().join("fresh.bin");
        let resolved = policy.validate_download_path(&fresh).unwrap();
        assert_eq!(
            resolved,
            std::fs::canonicalize(allowed.path())
                .unwrap()
                .join("fresh.bin")
        );

        assert!(policy.validate_download_path(&existing).is_err());
        assert!(
            policy
                .validate_download_path(&outside.path().join("nope.bin"))
                .is_err()
        );
        assert!(
            policy
                .validate_download_path(&symlink_dir.join("escape.bin"))
                .is_err()
        );
        assert!(policy.validate_download_path(Path::new("-")).is_err());
        assert!(
            policy
                .validate_download_path(Path::new("bare.bin"))
                .is_err()
        );
    }

    #[test]
    fn test_policy_fail_closed_when_allowed_dirs_empty() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"x").unwrap();

        let policy = McpPolicy::new(None, true, &[], 60).unwrap();
        assert!(policy.validate_upload_path(&file).is_err());
        assert!(
            policy
                .validate_download_path(&dir.path().join("b.txt"))
                .is_err()
        );
    }
}
