pub mod params;
pub mod policy;
pub mod server;
pub mod skill;

use anyhow::Context as _;
use rmcp::ServiceExt as _;

pub use skill::SkillTarget;

#[derive(Debug, Clone)]
pub struct McpServeOpts {
    pub account: Option<String>,
    pub allow_write: bool,
    pub allowed_dirs: Vec<std::path::PathBuf>,
    pub unlock_timeout_secs: u64,
}

pub fn serve(opts: McpServeOpts) -> anyhow::Result<()> {
    let policy = policy::McpPolicy::new(
        opts.account,
        opts.allow_write,
        &opts.allowed_dirs,
        opts.unlock_timeout_secs,
    )?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to initialize tokio runtime for MCP server")?;

    runtime.block_on(async move {
        let server = server::RbwMcpServer::new(policy);
        let service =
            server
                .serve(rmcp::transport::stdio())
                .await
                .map_err(|err| {
                    anyhow::anyhow!("MCP server failed to start: {err}")
                })?;
        service.waiting().await.map_err(|err| {
            anyhow::anyhow!("MCP server task failed: {err}")
        })?;
        Ok(())
    })
}

pub fn install_skill(
    target: SkillTarget,
    dir: Option<&std::path::Path>,
    force: bool,
) -> anyhow::Result<()> {
    let installed = skill::install_skill(target, dir, force)?;
    for path in installed {
        println!("Installed rbw skill to {}", path.display());
    }
    Ok(())
}
