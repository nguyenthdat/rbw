use std::{path::Path, sync::Arc};

use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, ContentBlock, GetSkillRequestParams, GetSkillResult,
        Implementation, ListResourcesResult, ListSkillsResult,
        PaginatedRequestParams, ProtocolVersion,
        ReadResourceDirectoryRequestParams, ReadResourceDirectoryResult,
        ReadResourceRequestParams, ReadResourceResponse, ServerCapabilities,
        ServerConfig,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};

use crate::{
    commands::mcp_ops,
    mcp::{
        params::{
            AttachmentAction, DeleteTarget, GetMode, SessionAction,
            VaultAttachmentParams, VaultDeleteParams, VaultGenerateParams,
            VaultGetParams, VaultSearchParams, VaultSessionParams,
            VaultStatusParams, VaultWriteParams, WriteAction,
        },
        policy::McpPolicy,
        skill::EmbeddedSkillBundle,
    },
};

const SERVER_INSTRUCTIONS: &str = "Local Bitwarden / Vaultwarden MCP 2.0 server backed by rbw-agent. \
    Prefer vault_status -> vault_search (metadata only) -> vault_get(mode='summary') -> \
    vault_get(mode='field' or 'totp', copy_to_clipboard=true) to minimize secret exposure. \
    Never ask for master passwords in chat; call vault_session(action='unlock') for out-of-band unlock. \
    Read the bundled agent skill at skill://rbw/SKILL.md for full workflows.";

#[derive(Clone)]
pub struct RbwMcpServer {
    policy: Arc<McpPolicy>,
    skill_bundle: Arc<EmbeddedSkillBundle>,
    tool_router: ToolRouter<Self>,
}

impl RbwMcpServer {
    pub fn new(policy: McpPolicy) -> Self {
        let mut tool_router = Self::core_tool_router();
        if policy.allow_write {
            tool_router.merge(Self::write_tool_router());
        }
        if !policy.allowed_dirs.is_empty() {
            tool_router.merge(Self::attachment_tool_router());
        }
        Self {
            policy: Arc::new(policy),
            skill_bundle: Arc::new(EmbeddedSkillBundle::new()),
            tool_router,
        }
    }
}

fn ok_json<T: serde::Serialize>(value: &T) -> CallToolResult {
    match serde_json::to_value(value) {
        Ok(json_val) => CallToolResult::structured(json_val),
        Err(err) => {
            err_result(format!("failed to serialize tool response: {err}"))
        }
    }
}

fn err_result(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

async fn run_blocking_tool<T, F>(f: F) -> CallToolResult
where
    T: serde::Serialize + Send + 'static,
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(report)) => ok_json(&report),
        Ok(Err(err)) => err_result(format!("{err:#}")),
        Err(join_err) => {
            err_result(format!("internal worker error: {join_err}"))
        }
    }
}

#[tool_router(router = core_tool_router)]
impl RbwMcpServer {
    #[tool(
        name = "vault_status",
        description = "Check rbw-agent status, configured accounts, lock state, and optionally list vault folders.",
        annotations(
            title = "Vault Status & Accounts",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vault_status(
        &self,
        Parameters(params): Parameters<VaultStatusParams>,
    ) -> CallToolResult {
        let account = self
            .policy
            .resolve_account(params.account.as_deref())
            .map(str::to_string);
        let include_folders = params.include_folders;
        run_blocking_tool(move || {
            mcp_ops::status(account.as_deref(), include_folders)
        })
        .await
    }

    #[tool(
        name = "vault_search",
        description = "List or search vault entries. Returns metadata only (id, name, type, username, folder, URIs, TOTP/attachment flags) and never returns secrets.",
        annotations(
            title = "Search Vault Entries",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vault_search(
        &self,
        Parameters(params): Parameters<VaultSearchParams>,
    ) -> CallToolResult {
        let account = self
            .policy
            .resolve_account(params.account.as_deref())
            .map(str::to_string);
        let limit = params.limit.unwrap_or(50);
        let offset = params.offset.unwrap_or(0);
        let entry_type = params.entry_type.map(Into::into);
        run_blocking_tool(move || {
            mcp_ops::search(
                account.as_deref(),
                params.query.as_deref(),
                params.url.as_deref(),
                params.folder.as_deref(),
                entry_type,
                limit,
                offset,
            )
        })
        .await
    }

    #[tool(
        name = "vault_get",
        description = "Retrieve a vault entry by UUID, name, or URL. Defaults to mode='summary' (no secrets). Supports mode='field', 'totp', 'history', 'full', and copy_to_clipboard=true to avoid exposing secrets in chat.",
        annotations(
            title = "Get Vault Entry or Secret",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn vault_get(
        &self,
        Parameters(params): Parameters<VaultGetParams>,
    ) -> CallToolResult {
        if params.query.trim().is_empty() {
            return err_result("`query` cannot be empty");
        }
        let account = self
            .policy
            .resolve_account(params.account.as_deref())
            .map(str::to_string);

        match params.mode {
            GetMode::Summary => {
                if params.copy_to_clipboard {
                    return err_result(
                        "`copy_to_clipboard` is only valid with mode='field', 'totp', or 'history' (with `version`)",
                    );
                }
                run_blocking_tool(move || {
                    mcp_ops::get_summary(
                        account.as_deref(),
                        &params.query,
                        params.username.as_deref(),
                        params.folder.as_deref(),
                        params.ignore_case,
                    )
                })
                .await
            }
            GetMode::Field => {
                let Some(field) = params
                    .field
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                else {
                    return err_result(
                        "`field` is required when mode='field' (call mode='summary' first to inspect available_fields)",
                    );
                };
                run_blocking_tool(move || {
                    mcp_ops::get_field(
                        account.as_deref(),
                        &params.query,
                        &field,
                        params.username.as_deref(),
                        params.folder.as_deref(),
                        params.ignore_case,
                        params.copy_to_clipboard,
                    )
                })
                .await
            }
            GetMode::Totp => {
                run_blocking_tool(move || {
                    mcp_ops::get_totp(
                        account.as_deref(),
                        &params.query,
                        params.username.as_deref(),
                        params.folder.as_deref(),
                        params.ignore_case,
                        params.copy_to_clipboard,
                    )
                })
                .await
            }
            GetMode::History => {
                run_blocking_tool(move || {
                    mcp_ops::get_history(
                        account.as_deref(),
                        &params.query,
                        params.version.as_deref(),
                        params.username.as_deref(),
                        params.folder.as_deref(),
                        params.ignore_case,
                        params.copy_to_clipboard,
                    )
                })
                .await
            }
            GetMode::Full => {
                if params.copy_to_clipboard {
                    return err_result(
                        "`copy_to_clipboard` is not supported with mode='full'; use mode='field' instead",
                    );
                }
                run_blocking_tool(move || {
                    mcp_ops::get_full(
                        account.as_deref(),
                        &params.query,
                        params.username.as_deref(),
                        params.folder.as_deref(),
                        params.ignore_case,
                    )
                })
                .await
            }
        }
    }

    #[allow(clippy::unused_self)]
    #[tool(
        name = "vault_generate",
        description = "Generate a random password or EFF diceware passphrase without modifying the vault.",
        annotations(
            title = "Generate Password",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    fn vault_generate(
        &self,
        Parameters(params): Parameters<VaultGenerateParams>,
    ) -> CallToolResult {
        let len = match params.style.resolve_length(params.length) {
            Ok(len) => len,
            Err(err) => return err_result(format!("{err:#}")),
        };
        let pw_type = params.style.into_pwgen_type();
        let style_name = params.style.as_str();
        let password = rbw::pwgen::pwgen(pw_type, len);
        ok_json(&serde_json::json!({
            "password": password,
            "length": len,
            "style": style_name,
        }))
    }

    #[tool(
        name = "vault_session",
        description = "Unlock (out-of-band via local Touch ID/YubiKey/pinentry, never takes a password), lock, sync, or switch active account.",
        annotations(
            title = "Manage Vault Session",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn vault_session(
        &self,
        Parameters(params): Parameters<VaultSessionParams>,
    ) -> CallToolResult {
        let account = self
            .policy
            .resolve_account(params.account.as_deref())
            .map(str::to_string);

        match params.action {
            SessionAction::Unlock => {
                let timeout = self.policy.unlock_timeout;
                let task = tokio::task::spawn_blocking(move || {
                    mcp_ops::session_unlock(account.as_deref())
                });
                match tokio::time::timeout(timeout, task).await {
                    Ok(Ok(Ok(report))) => ok_json(&report),
                    Ok(Ok(Err(err))) => err_result(format!("{err:#}")),
                    Ok(Err(join_err)) => err_result(format!(
                        "internal worker error: {join_err}"
                    )),
                    Err(_) => err_result(format!(
                        "unlock timed out after {}s waiting for local Touch ID / YubiKey / pinentry; \
                         unlock in a terminal with `rbw unlock` or retry",
                        timeout.as_secs()
                    )),
                }
            }
            SessionAction::Lock => {
                run_blocking_tool(move || {
                    mcp_ops::session_lock(account.as_deref(), params.all)
                })
                .await
            }
            SessionAction::Sync => {
                run_blocking_tool(move || {
                    mcp_ops::session_sync(account.as_deref())
                })
                .await
            }
            SessionAction::SwitchAccount => {
                run_blocking_tool(move || {
                    mcp_ops::session_switch_account(
                        params.target.as_deref(),
                        params.email.as_deref(),
                        params.server.as_deref(),
                    )
                })
                .await
            }
        }
    }
}

#[tool_router(router = write_tool_router)]
impl RbwMcpServer {
    #[tool(
        name = "vault_write",
        description = "Create or partially update a vault item (login, note, card, identity) or create a folder. Supports server-side password generation and preserves password history on updates.",
        annotations(
            title = "Create or Update Vault Item/Folder",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn vault_write(
        &self,
        Parameters(params): Parameters<VaultWriteParams>,
    ) -> CallToolResult {
        if !self.policy.allow_write {
            return err_result(
                "write operations are disabled; restart server with `rbw mcp --allow-write`",
            );
        }
        let account = self
            .policy
            .resolve_account(params.account.as_deref())
            .map(str::to_string);

        let gen_spec = match params.generate_password {
            Some(spec) => match spec.style.resolve_length(spec.length) {
                Ok(len) => Some((spec.style.into_pwgen_type(), len)),
                Err(err) => return err_result(format!("{err:#}")),
            },
            None => None,
        };

        match params.action {
            WriteAction::CreateFolder => {
                let Some(name) = params.name else {
                    return err_result(
                        "`name` is required for action='create_folder'",
                    );
                };
                run_blocking_tool(move || {
                    mcp_ops::create_folder(account.as_deref(), &name)
                })
                .await
            }
            WriteAction::CreateItem => {
                let Some(name) = params.name else {
                    return err_result(
                        "`name` is required for action='create_item'",
                    );
                };
                let entry_type = params
                    .entry_type
                    .map_or(mcp_ops::EntryKind::Login, Into::into);
                let input = mcp_ops::CreateItemInput {
                    entry_type,
                    name,
                    folder: params.folder,
                    notes: params.notes,
                    fields: params
                        .fields
                        .unwrap_or_default()
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                    login: params.login.map(Into::into),
                    card: params.card.map(Into::into),
                    identity: params.identity.map(Into::into),
                    generate_password: gen_spec,
                };
                run_blocking_tool(move || {
                    mcp_ops::create_item(account.as_deref(), input)
                })
                .await
            }
            WriteAction::UpdateItem => {
                let Some(query) = params
                    .query
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                else {
                    return err_result(
                        "`query` (entry UUID, name, or URL) is required for action='update_item'",
                    );
                };
                let input = mcp_ops::UpdateItemInput {
                    query,
                    match_username: params.match_username,
                    match_folder: params.match_folder,
                    ignore_case: params.ignore_case,
                    name: params.name,
                    folder: params.folder,
                    clear_folder: params.clear_folder,
                    notes: params.notes,
                    fields: params
                        .fields
                        .map(|fs| fs.into_iter().map(Into::into).collect()),
                    login: params.login.map(Into::into),
                    card: params.card.map(Into::into),
                    identity: params.identity.map(Into::into),
                    generate_password: gen_spec,
                };
                run_blocking_tool(move || {
                    mcp_ops::update_item(account.as_deref(), input)
                })
                .await
            }
        }
    }

    #[tool(
        name = "vault_delete",
        description = "Permanently delete a vault item or attachment. Always confirm the target with the user first.",
        annotations(
            title = "Delete Vault Item or Attachment",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn vault_delete(
        &self,
        Parameters(params): Parameters<VaultDeleteParams>,
    ) -> CallToolResult {
        if !self.policy.allow_write {
            return err_result(
                "delete operations are disabled; restart server with `rbw mcp --allow-write`",
            );
        }
        if params.query.trim().is_empty() {
            return err_result("`query` cannot be empty");
        }
        let account = self
            .policy
            .resolve_account(params.account.as_deref())
            .map(str::to_string);

        match params.target {
            DeleteTarget::Item => {
                run_blocking_tool(move || {
                    mcp_ops::delete_item(
                        account.as_deref(),
                        &params.query,
                        params.username.as_deref(),
                        params.folder.as_deref(),
                        params.ignore_case,
                    )
                })
                .await
            }
            DeleteTarget::Attachment => {
                let Some(attachment) = params
                    .attachment
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                else {
                    return err_result(
                        "`attachment` (ID or exact filename) is required when target='attachment'",
                    );
                };
                run_blocking_tool(move || {
                    mcp_ops::delete_attachment(
                        account.as_deref(),
                        &params.query,
                        &attachment,
                        params.username.as_deref(),
                        params.folder.as_deref(),
                        params.ignore_case,
                    )
                })
                .await
            }
        }
    }
}

#[tool_router(router = attachment_tool_router)]
impl RbwMcpServer {
    #[tool(
        name = "vault_attachment",
        description = "Download or upload a vault entry attachment within configured --allowed-dir directories. Downloads write atomically (0600, no-clobber); uploads also require --allow-write.",
        annotations(
            title = "Transfer Vault Attachment",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn vault_attachment(
        &self,
        Parameters(params): Parameters<VaultAttachmentParams>,
    ) -> CallToolResult {
        if params.query.trim().is_empty() {
            return err_result("`query` cannot be empty");
        }
        let account = self
            .policy
            .resolve_account(params.account.as_deref())
            .map(str::to_string);

        match params.action {
            AttachmentAction::Download => {
                let Some(attachment) = params
                    .attachment
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                else {
                    return err_result(
                        "`attachment` (ID or exact filename) is required for action='download'",
                    );
                };
                let target_path = match self
                    .policy
                    .validate_download_path(Path::new(&params.path))
                {
                    Ok(path) => path,
                    Err(err) => return err_result(format!("{err:#}")),
                };
                run_blocking_tool(move || {
                    mcp_ops::download_attachment(
                        account.as_deref(),
                        &params.query,
                        &attachment,
                        &target_path,
                        params.username.as_deref(),
                        params.folder.as_deref(),
                        params.ignore_case,
                    )
                })
                .await
            }
            AttachmentAction::Upload => {
                if !self.policy.allow_write {
                    return err_result(
                        "attachment upload requires --allow-write in addition to --allowed-dir",
                    );
                }
                let source_path = match self
                    .policy
                    .validate_upload_path(Path::new(&params.path))
                {
                    Ok(path) => path,
                    Err(err) => return err_result(format!("{err:#}")),
                };
                run_blocking_tool(move || {
                    mcp_ops::upload_attachment(
                        account.as_deref(),
                        &params.query,
                        &source_path,
                        params.file_name.as_deref(),
                        params.username.as_deref(),
                        params.folder.as_deref(),
                        params.ignore_case,
                    )
                })
                .await
            }
        }
    }
}

#[allow(clippy::unused_async_trait_impl)]
#[tool_handler(router = self.tool_router)]
impl ServerHandler for RbwMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_skills_with_directory_read()
                .build(),
        )
        .with_protocol_version(ProtocolVersion::LATEST)
        .with_server_info(Implementation::new(
            "rbw",
            env!("CARGO_PKG_VERSION"),
        ))
        .with_instructions(SERVER_INSTRUCTIONS)
    }

    fn list_skills(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListSkillsResult, ErrorData>>
    + Send
    + '_ {
        std::future::ready(Ok(self.skill_bundle.list_skills()))
    }

    fn get_skill(
        &self,
        request: GetSkillRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<GetSkillResult, ErrorData>>
    + Send
    + '_ {
        std::future::ready(self.skill_bundle.get_skill(&request.uri))
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<
        Output = Result<ListResourcesResult, ErrorData>,
    > + Send
    + '_ {
        std::future::ready(Ok(EmbeddedSkillBundle::list_resources()))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<
        Output = Result<ReadResourceResponse, ErrorData>,
    > + Send
    + '_ {
        std::future::ready(EmbeddedSkillBundle::read_resource(&request.uri))
    }

    fn read_resource_directory(
        &self,
        request: ReadResourceDirectoryRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<
        Output = Result<ReadResourceDirectoryResult, ErrorData>,
    > + Send
    + '_ {
        std::future::ready(EmbeddedSkillBundle::read_resource_directory(
            &request.uri,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::ServiceExt as _;
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    struct JsonRpcClient {
        reader: tokio::io::BufReader<
            tokio::io::ReadHalf<tokio::io::DuplexStream>,
        >,
        writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
        next_id: u64,
    }

    impl JsonRpcClient {
        fn new(stream: tokio::io::DuplexStream) -> Self {
            let (read_half, write_half) = tokio::io::split(stream);
            Self {
                reader: tokio::io::BufReader::new(read_half),
                writer: write_half,
                next_id: 1,
            }
        }

        async fn send_raw(&mut self, msg: &serde_json::Value) {
            let mut line = serde_json::to_string(msg).unwrap();
            line.push('\n');
            self.writer.write_all(line.as_bytes()).await.unwrap();
            self.writer.flush().await.unwrap();
        }

        async fn request(
            &mut self,
            method: &str,
            params: Option<serde_json::Value>,
        ) -> serde_json::Value {
            let id = self.next_id;
            self.next_id += 1;
            let mut body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
            });
            if let Some(p) = params {
                body["params"] = p;
            }
            self.send_raw(&body).await;
            let mut line = String::new();
            self.reader.read_line(&mut line).await.unwrap();
            serde_json::from_str(&line).unwrap()
        }

        async fn initialize_latest(&mut self) -> serde_json::Value {
            let resp = self
                .request(
                    "initialize",
                    Some(serde_json::json!({
                        "protocolVersion": "2026-07-28",
                        "capabilities": {},
                        "clientInfo": {"name": "test-client", "version": "1.0.0"}
                    })),
                )
                .await;
            self.send_raw(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }))
            .await;
            resp
        }
    }

    fn start_server(
        policy: McpPolicy,
    ) -> (JsonRpcClient, tokio::task::JoinHandle<()>) {
        let (server_io, client_io) = tokio::io::duplex(65536);
        let server = RbwMcpServer::new(policy);
        let handle = tokio::spawn(async move {
            if let Ok(running) = server.serve(server_io).await {
                let _ = running.waiting().await;
            }
        });
        (JsonRpcClient::new(client_io), handle)
    }

    #[tokio::test]
    async fn test_mcp_discover_2026_07_28_and_readonly_tools() {
        // MCP 2.0 (2026-07-28) inline discovery handshake
        let policy = McpPolicy::new(None, false, &[], 60).unwrap();
        let (mut client, handle) = start_server(policy);

        let discover = client
            .request(
                "server/discover",
                Some(serde_json::json!({
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientInfo": {
                            "name": "test-client",
                            "version": "1.0.0"
                        },
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                })),
            )
            .await;
        assert_eq!(discover["result"]["resultType"], "complete");
        let versions =
            discover["result"]["supportedVersions"].as_array().unwrap();
        assert!(versions.iter().any(|v| v == "2026-07-28"));
        assert_eq!(
            discover["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]
                ["name"],
            "rbw"
        );
        assert_eq!(
            discover["result"]["capabilities"]["extensions"]["io.modelcontextprotocol/skills"]
                ["directoryRead"],
            true
        );
        drop(client);
        handle.await.unwrap();

        // Session-mode initialize (2025-11-25) + read-only tools/list & annotations
        let policy = McpPolicy::new(None, false, &[], 60).unwrap();
        let (mut client, handle) = start_server(policy);

        let init = client.initialize_latest().await;
        assert_eq!(init["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(init["result"]["serverInfo"]["name"], "rbw");
        assert!(init["result"]["capabilities"]["tools"].is_object());
        assert!(init["result"]["capabilities"]["resources"].is_object());
        assert_eq!(
            init["result"]["capabilities"]["extensions"]["io.modelcontextprotocol/skills"]
                ["directoryRead"],
            true
        );

        let list = client.request("tools/list", None).await;
        let tools = list["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> =
            tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            vec![
                "vault_generate",
                "vault_get",
                "vault_search",
                "vault_session",
                "vault_status",
            ]
        );

        for tool in tools {
            let ann = tool["annotations"].as_object().unwrap();
            let name = tool["name"].as_str().unwrap();
            assert_eq!(ann["destructiveHint"], false, "{name}");
            if name == "vault_session" {
                assert_eq!(ann["readOnlyHint"], false);
            } else {
                assert_eq!(ann["readOnlyHint"], true, "{name}");
            }
        }

        drop(client);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_mcp_tool_registration_with_write_and_allowed_dirs() {
        let dir = tempfile::tempdir().unwrap();

        // --allow-write only -> 7 tools (vault_write + vault_delete)
        let write_policy = McpPolicy::new(None, true, &[], 60).unwrap();
        let (mut client, handle) = start_server(write_policy);
        let _ = client.initialize_latest().await;
        let list = client.request("tools/list", None).await;
        let tools = list["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> =
            tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            vec![
                "vault_delete",
                "vault_generate",
                "vault_get",
                "vault_search",
                "vault_session",
                "vault_status",
                "vault_write",
            ]
        );
        let delete_tool =
            tools.iter().find(|t| t["name"] == "vault_delete").unwrap();
        assert_eq!(delete_tool["annotations"]["destructiveHint"], true);
        drop(client);
        handle.await.unwrap();

        // --allowed-dir without --allow-write -> 6 tools; upload rejected
        let dl_policy =
            McpPolicy::new(None, false, &[dir.path().to_path_buf()], 60)
                .unwrap();
        let (mut client, handle) = start_server(dl_policy);
        let _ = client.initialize_latest().await;
        let list = client.request("tools/list", None).await;
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), 6);
        assert!(names.contains(&"vault_attachment"));

        let upload_resp = client
            .request(
                "tools/call",
                Some(serde_json::json!({
                    "name": "vault_attachment",
                    "arguments": {
                        "action": "upload",
                        "query": "demo",
                        "path": dir.path().join("x.txt").to_string_lossy()
                    }
                })),
            )
            .await;
        assert_eq!(upload_resp["result"]["isError"], true);
        assert!(
            upload_resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("--allow-write")
        );
        drop(client);
        handle.await.unwrap();

        // Both --allow-write and --allowed-dir -> 8 tools
        let full_policy =
            McpPolicy::new(None, true, &[dir.path().to_path_buf()], 60)
                .unwrap();
        let (mut client, handle) = start_server(full_policy);
        let _ = client.initialize_latest().await;
        let list = client.request("tools/list", None).await;
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 8);
        drop(client);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_mcp_vault_generate_and_validation() {
        let policy = McpPolicy::new(None, false, &[], 60).unwrap();
        let (mut client, handle) = start_server(policy);
        let _ = client.initialize_latest().await;

        let res = client
            .request(
                "tools/call",
                Some(serde_json::json!({
                    "name": "vault_generate",
                    "arguments": {"length": 24, "style": "numbers"}
                })),
            )
            .await;
        assert_eq!(res["result"]["isError"], false);
        let pw = res["result"]["structuredContent"]["password"]
            .as_str()
            .unwrap();
        assert_eq!(pw.len(), 24);
        assert!(pw.bytes().all(|b| b.is_ascii_digit()));

        let dice = client
            .request(
                "tools/call",
                Some(serde_json::json!({
                    "name": "vault_generate",
                    "arguments": {"length": 6, "style": "diceware"}
                })),
            )
            .await;
        assert_eq!(dice["result"]["isError"], false);
        let phrase = dice["result"]["structuredContent"]["password"]
            .as_str()
            .unwrap();
        assert_eq!(phrase.split(' ').count(), 6);

        let bad = client
            .request(
                "tools/call",
                Some(serde_json::json!({
                    "name": "vault_generate",
                    "arguments": {"length": 999, "style": "all_chars"}
                })),
            )
            .await;
        assert_eq!(bad["result"]["isError"], true);

        drop(client);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_mcp_sep_2640_skills_and_resources_end_to_end() {
        let policy = McpPolicy::new(None, false, &[], 60).unwrap();
        let (mut client, handle) = start_server(policy);
        let _ = client.initialize_latest().await;

        let skills_list = client.request("skills/list", None).await;
        let skills = skills_list["result"]["skills"].as_array().unwrap();
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0]["uri"], "skill://rbw/SKILL.md");
        assert_eq!(skills[0]["frontmatter"]["name"], "rbw");

        let skill_get = client
            .request(
                "skills/get",
                Some(serde_json::json!({"uri": "skill://rbw/SKILL.md"})),
            )
            .await;
        let manifest_files = skill_get["result"]["skill"]["resources"]
            .as_array()
            .unwrap();
        assert_eq!(manifest_files.len(), 3);

        let dir_root = client
            .request(
                "resources/directory/read",
                Some(serde_json::json!({"uri": "skill://rbw"})),
            )
            .await;
        let entries = dir_root["result"]["resources"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| {
            e["uri"] == "skill://rbw/references"
                && e["mimeType"] == "inode/directory"
        }));

        for entry in manifest_files {
            let uri = entry["uri"].as_str().unwrap();
            let expected_digest = entry["digest"].as_str().unwrap();
            let expected_size = entry["size"].as_u64().unwrap();
            let read_res = client
                .request(
                    "resources/read",
                    Some(serde_json::json!({"uri": uri})),
                )
                .await;
            let text =
                read_res["result"]["contents"][0]["text"].as_str().unwrap();
            let check = rmcp::model::SkillResource::new(
                uri,
                expected_digest,
                expected_size,
            );
            assert_eq!(
                check.verify(text.as_bytes()),
                Ok(()),
                "digest for {uri}"
            );
        }

        drop(client);
        handle.await.unwrap();
    }
}
