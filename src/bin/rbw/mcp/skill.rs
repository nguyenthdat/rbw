use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use rmcp::{
    ErrorData,
    model::{
        DIRECTORY_MIME_TYPE, GetSkillResult, ListResourcesResult,
        ListSkillsResult, ReadResourceDirectoryResult, ReadResourceResponse,
        ReadResourceResult, Resource, ResourceContents, Skill,
        SkillFrontmatter, SkillResource, SkillResources,
    },
};

pub const SKILL_NAME: &str = "rbw";
pub const SKILL_DESCRIPTION: &str = "Bitwarden vault passwords, TOTP, SSH keys, notes, folders via rbw MCP server or CLI";

pub const SKILL_ROOT_URI: &str = "skill://rbw";
pub const SKILL_MD_URI: &str = "skill://rbw/SKILL.md";
pub const REFERENCES_DIR_URI: &str = "skill://rbw/references";
pub const TOOLS_REF_URI: &str = "skill://rbw/references/tools.md";
pub const WORKFLOWS_REF_URI: &str = "skill://rbw/references/workflows.md";

const SKILL_MD_CONTENT: &str =
    include_str!("../../../../skills/rbw/SKILL.md");
const TOOLS_REF_CONTENT: &str =
    include_str!("../../../../skills/rbw/references/tools.md");
const WORKFLOWS_REF_CONTENT: &str =
    include_str!("../../../../skills/rbw/references/workflows.md");

struct EmbeddedFile {
    uri: &'static str,
    rel_path: &'static str,
    name: &'static str,
    description: &'static str,
    content: &'static str,
}

const EMBEDDED_FILES: &[EmbeddedFile] = &[
    EmbeddedFile {
        uri: SKILL_MD_URI,
        rel_path: "SKILL.md",
        name: "SKILL.md",
        description: "rbw Bitwarden vault Agent Skill entry point",
        content: SKILL_MD_CONTENT,
    },
    EmbeddedFile {
        uri: TOOLS_REF_URI,
        rel_path: "references/tools.md",
        name: "tools.md",
        description: "rbw MCP tool schemas, availability matrix, and error recovery",
        content: TOOLS_REF_CONTENT,
    },
    EmbeddedFile {
        uri: WORKFLOWS_REF_URI,
        rel_path: "references/workflows.md",
        name: "workflows.md",
        description: "Step-by-step rbw vault workflows and CLI fallback commands",
        content: WORKFLOWS_REF_CONTENT,
    },
];

#[derive(Debug, Clone)]
pub struct EmbeddedSkillBundle {
    skill: Skill,
}

impl EmbeddedSkillBundle {
    pub fn new() -> Self {
        let resources = EMBEDDED_FILES
            .iter()
            .map(|f| SkillResource::from_bytes(f.uri, f.content.as_bytes()))
            .collect();
        let skill = Skill::new(
            SKILL_MD_URI,
            SkillFrontmatter::new(SKILL_NAME, SKILL_DESCRIPTION),
            SkillResources::Files(resources),
        );
        debug_assert!(skill.validate().is_ok());
        Self { skill }
    }

    pub fn list_skills(&self) -> ListSkillsResult {
        ListSkillsResult::with_all_items(vec![self.skill.clone()])
    }

    pub fn get_skill(&self, uri: &str) -> Result<GetSkillResult, ErrorData> {
        if uri == SKILL_MD_URI {
            Ok(GetSkillResult::new(self.skill.clone()))
        } else {
            Err(ErrorData::invalid_params(
                format!("unknown skill URI '{uri}'"),
                None,
            ))
        }
    }

    pub fn list_resources() -> ListResourcesResult {
        let items = EMBEDDED_FILES
            .iter()
            .map(|f| {
                Resource::new(f.uri, f.name)
                    .with_description(f.description)
                    .with_mime_type("text/markdown")
                    .with_size(
                        u64::try_from(f.content.len()).unwrap_or(u64::MAX),
                    )
            })
            .collect();
        ListResourcesResult::with_all_items(items)
    }

    pub fn read_resource(
        uri: &str,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let Some(file) = EMBEDDED_FILES.iter().find(|f| f.uri == uri) else {
            return Err(ErrorData::resource_not_found(
                format!("no skill resource at '{uri}'"),
                None,
            ));
        };
        Ok(ReadResourceResult::new(vec![
            ResourceContents::text(file.content, file.uri)
                .with_mime_type("text/markdown"),
        ])
        .into())
    }

    pub fn read_resource_directory(
        uri: &str,
    ) -> Result<ReadResourceDirectoryResult, ErrorData> {
        let normalized = uri.trim_end_matches('/');
        match normalized {
            SKILL_ROOT_URI => Ok(ListResourcesResult::with_all_items(vec![
                Resource::new(SKILL_MD_URI, "SKILL.md")
                    .with_mime_type("text/markdown")
                    .with_size(
                        u64::try_from(SKILL_MD_CONTENT.len())
                            .unwrap_or(u64::MAX),
                    ),
                Resource::new(REFERENCES_DIR_URI, "references")
                    .with_mime_type(DIRECTORY_MIME_TYPE),
            ])),
            REFERENCES_DIR_URI => {
                Ok(ListResourcesResult::with_all_items(vec![
                    Resource::new(TOOLS_REF_URI, "tools.md")
                        .with_mime_type("text/markdown")
                        .with_size(
                            u64::try_from(TOOLS_REF_CONTENT.len())
                                .unwrap_or(u64::MAX),
                        ),
                    Resource::new(WORKFLOWS_REF_URI, "workflows.md")
                        .with_mime_type("text/markdown")
                        .with_size(
                            u64::try_from(WORKFLOWS_REF_CONTENT.len())
                                .unwrap_or(u64::MAX),
                        ),
                ]))
            }
            _ => Err(ErrorData::invalid_params(
                format!("'{uri}' is not a skill directory"),
                None,
            )),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
pub enum SkillTarget {
    /// Cross-agent standard directory (~/.agents/skills/rbw)
    #[default]
    Agents,
    /// Google Antigravity (~/.gemini/config/skills/rbw)
    Agy,
    /// Oh My Pi (~/.omp/agent/skills/rbw)
    Omp,
    /// Claude Code (~/.claude/skills/rbw)
    Claude,
    /// Install to all standard agent directories (agents, agy, omp, claude)
    All,
}

fn target_destinations(
    target: SkillTarget,
    custom_dir: Option<&Path>,
) -> anyhow::Result<Vec<PathBuf>> {
    if let Some(dir) = custom_dir {
        return Ok(vec![dir.to_path_buf()]);
    }
    let home = directories::BaseDirs::new()
        .context("could not determine user home directory")?
        .home_dir()
        .to_path_buf();

    let dirs = match target {
        SkillTarget::Agents => vec![home.join(".agents/skills/rbw")],
        SkillTarget::Agy => vec![home.join(".gemini/config/skills/rbw")],
        SkillTarget::Omp => vec![home.join(".omp/agent/skills/rbw")],
        SkillTarget::Claude => vec![home.join(".claude/skills/rbw")],
        SkillTarget::All => vec![
            home.join(".agents/skills/rbw"),
            home.join(".gemini/config/skills/rbw"),
            home.join(".omp/agent/skills/rbw"),
            home.join(".claude/skills/rbw"),
        ],
    };
    Ok(dirs)
}

pub fn install_skill(
    target: SkillTarget,
    custom_dir: Option<&Path>,
    force: bool,
) -> anyhow::Result<Vec<PathBuf>> {
    let destinations = target_destinations(target, custom_dir)?;
    for dest in &destinations {
        install_skill_to_dir(dest, force)?;
    }
    Ok(destinations)
}

fn install_skill_to_dir(dest: &Path, force: bool) -> anyhow::Result<()> {
    if !force {
        for file in EMBEDDED_FILES {
            let path = dest.join(file.rel_path);
            if path.exists() {
                anyhow::bail!(
                    "skill file '{}' already exists; re-run with --force to overwrite",
                    path.display()
                );
            }
        }
    }

    for file in EMBEDDED_FILES {
        let path = dest.join(file.rel_path);
        let parent = path
            .parent()
            .context("embedded skill file must have parent directory")?;
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create directory '{}'", parent.display())
        })?;
        let mut tmp =
            tempfile::NamedTempFile::new_in(parent).with_context(|| {
                format!(
                    "failed to create temp file in '{}'",
                    parent.display()
                )
            })?;
        tmp.write_all(file.content.as_bytes()).with_context(|| {
            format!("failed to write skill file '{}'", path.display())
        })?;
        tmp.as_file().sync_all().with_context(|| {
            format!("failed to flush skill file '{}'", path.display())
        })?;
        if force {
            tmp.persist(&path).map_err(|e| e.error).with_context(|| {
                format!("failed to persist skill file '{}'", path.display())
            })?;
        } else {
            tmp.persist_noclobber(&path)
                .map_err(|e| e.error)
                .with_context(|| {
                    format!(
                        "failed to persist skill file '{}' (already exists)",
                        path.display()
                    )
                })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_skill_validates_and_matches_frontmatter() {
        let bundle = EmbeddedSkillBundle::new();
        let list = bundle.list_skills();
        assert_eq!(list.skills.len(), 1);
        let skill = &list.skills[0];
        assert_eq!(skill.validate(), Ok(()));
        assert_eq!(skill.uri, SKILL_MD_URI);
        assert_eq!(skill.name(), SKILL_NAME);
        assert_eq!(skill.frontmatter.description, SKILL_DESCRIPTION);

        // Ensure frontmatter constants stay in sync with SKILL.md
        assert!(SKILL_MD_CONTENT.contains(&format!("name: {SKILL_NAME}\n")));
        assert!(
            SKILL_MD_CONTENT
                .contains(&format!("description: \"{SKILL_DESCRIPTION}\"\n"))
        );

        let SkillResources::Files(ref files) = skill.resources else {
            panic!("expected file manifest");
        };
        assert_eq!(files.len(), 3);
        for (manifest_entry, embedded) in
            files.iter().zip(EMBEDDED_FILES.iter())
        {
            assert_eq!(manifest_entry.uri, embedded.uri);
            assert_eq!(
                manifest_entry.verify(embedded.content.as_bytes()),
                Ok(())
            );
        }
    }

    #[test]
    fn test_install_skill_creates_and_respects_force() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("rbw");

        install_skill(SkillTarget::Agents, Some(&dest), false).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("SKILL.md")).unwrap(),
            SKILL_MD_CONTENT
        );
        assert_eq!(
            std::fs::read_to_string(dest.join("references/tools.md"))
                .unwrap(),
            TOOLS_REF_CONTENT
        );
        assert_eq!(
            std::fs::read_to_string(dest.join("references/workflows.md"))
                .unwrap(),
            WORKFLOWS_REF_CONTENT
        );

        // Fails without --force when files exist
        assert!(
            install_skill(SkillTarget::Agents, Some(&dest), false).is_err()
        );

        // Succeeds with --force and restores content
        std::fs::write(dest.join("SKILL.md"), "modified").unwrap();
        install_skill(SkillTarget::Agents, Some(&dest), true).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("SKILL.md")).unwrap(),
            SKILL_MD_CONTENT
        );
    }
}
