#![allow(unknown_lints, clippy::large_unopt_stack_frames)]

use std::io::Write as _;

use anyhow::Context as _;
use clap::{CommandFactory as _, Parser as _};

mod actions;
mod commands;
#[cfg(feature = "mcp")]
mod mcp;
mod prompt;
#[cfg(feature = "self-update")]
mod self_update;
mod sock;

#[derive(Debug, clap::Args)]
struct FindArgs {
    #[arg(help = "Name, URI or UUID of the entry to display", value_parser = commands::parse_needle)]
    needle: commands::Needle,
    #[arg(help = "Username of the entry to display")]
    user: Option<String>,
    #[arg(long, help = "Folder name to search in")]
    folder: Option<String>,
    #[arg(short, long, help = "Ignore case")]
    ignorecase: bool,
}

#[derive(Debug, clap::Parser)]
#[command(version, about = "Unofficial Bitwarden CLI")]
struct Cli {
    #[arg(
        short = 'a',
        long = "account",
        global = true,
        help = "Account name, email, or server to use for this command [env: RBW_ACCOUNT]"
    )]
    account: Option<String>,

    #[command(subcommand)]
    command: Opt,
}

#[derive(Debug, clap::Subcommand)]
enum Opt {
    #[command(about = "Manage multiple Bitwarden / Vaultwarden accounts")]
    Account {
        #[command(subcommand)]
        action: AccountAction,
    },

    #[command(about = "Switch the active Bitwarden account")]
    Switch {
        #[arg(help = "Account name, email, server, or email@server")]
        account: Option<String>,
        #[arg(short = 'e', long, help = "Filter by account email address")]
        email: Option<String>,
        #[arg(
            short = 's',
            long,
            help = "Filter by vault server host or URL"
        )]
        server: Option<String>,
    },

    #[command(about = "Get or set configuration options")]
    Config {
        #[command(subcommand)]
        config: Config,
    },

    #[command(
        about = "Register this device with the Bitwarden server",
        long_about = "Register this device with the Bitwarden server\n\n\
            The official Bitwarden server includes bot detection to prevent \
            brute force attacks. In order to avoid being detected as bot \
            traffic, you will need to use this command to log in with your \
            personal API key (instead of your password) first before regular \
            logins will work."
    )]
    Register,

    #[command(about = "Log in to the Bitwarden server")]
    Login {
        #[arg(
            long,
            conflicts_with = "password",
            help = "Log in using a FIDO2 passkey (WebAuthn PRF)"
        )]
        passkey: bool,
        #[arg(
            long,
            conflicts_with = "passkey",
            help = "Log in using master password (overrides passkey_login config)"
        )]
        password: bool,
    },

    #[command(about = "Manage FIDO2 / YubiKey local unlock keys")]
    Yubikey {
        #[command(subcommand)]
        action: YubikeyAction,
    },

    #[command(about = "Unlock the local Bitwarden database")]
    Unlock,

    #[command(about = "Check if the local Bitwarden database is unlocked")]
    Unlocked,

    #[command(about = "Update the local copy of the Bitwarden database")]
    Sync,

    #[command(
        about = "List all entries in the local Bitwarden database",
        visible_alias = "ls"
    )]
    List {
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder, type. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(about = "Display the password for a given entry")]
    Get {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(short, long, help = "Field to get")]
        field: Option<String>,
        #[arg(long, help = "Display the notes in addition to the password")]
        full: bool,
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
        #[cfg(feature = "clipboard")]
        #[arg(short, long, help = "Copy result to clipboard")]
        clipboard: bool,
        #[arg(short, long, help = "List fields in this entry")]
        list_fields: bool,
        #[arg(
            long,
            help = "Download an attachment by exact filename or ID",
            requires = "output",
            conflicts_with_all = ["field", "full", "raw", "list_fields"]
        )]
        #[cfg_attr(feature = "clipboard", arg(conflicts_with = "clipboard"))]
        attachment: Option<String>,
        #[arg(
            long,
            help = "Attachment output file, or - for binary stdout",
            requires = "attachment"
        )]
        output: Option<std::path::PathBuf>,
    },

    #[command(about = "Search for entries")]
    Search {
        #[arg(help = "Search term to locate entries")]
        term: String,
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(
        about = "Display the authenticator code for a given entry",
        visible_alias = "totp"
    )]
    Code {
        #[command(flatten)]
        find_args: FindArgs,
        #[cfg(feature = "clipboard")]
        #[arg(long, help = "Copy result to clipboard")]
        clipboard: bool,
    },

    #[command(
        about = "Add a new login or secure note entry to the database",
        long_about = "Add a new login or secure note entry to the database\n\n\
            This command will open a text editor (or read piped stdin) to \
            enter the entry contents. The editor to use is determined by the \
            value of the $VISUAL or $EDITOR environment variables.\n\n\
            For login entries (default), the first line will be saved as the \
            password and the remainder will be saved as a note.\n\
            For secure notes (--note / --type note), the entire content will \
            be saved as the note."
    )]
    Add {
        #[arg(help = "Name of the entry")]
        name: String,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the entry")]
        folder: Option<String>,
        #[arg(
            short = 't',
            long = "type",
            value_enum,
            conflicts_with = "note",
            help = "Type of entry to add (login or note)"
        )]
        entry_type: Option<commands::AddEntryType>,
        #[arg(
            long,
            conflicts_with_all = ["user", "uri", "entry_type"],
            help = "Add a secure note instead of a login entry"
        )]
        note: bool,
    },

    #[command(
        about = "Generate a new password",
        long_about = "Generate a new password\n\n\
            If given a password entry name, also save the generated \
            password to the database.",
        visible_alias = "gen",
        group = clap::ArgGroup::new("password-type").args(&[
            "no_symbols",
            "only_numbers",
            "nonconfusables",
            "diceware",
        ])
    )]
    Generate {
        #[arg(help = "Length of the password to generate")]
        len: usize,
        #[arg(help = "Name of the password entry")]
        name: Option<String>,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
        #[arg(
            long = "no-symbols",
            help = "Generate a password with no special characters"
        )]
        no_symbols: bool,
        #[arg(
            long = "only-numbers",
            help = "Generate a password consisting of only numbers"
        )]
        only_numbers: bool,
        #[arg(
            long,
            help = "Generate a password without visually similar \
                characters (useful for passwords intended to be \
                written down)"
        )]
        nonconfusables: bool,
        #[arg(
            long,
            help = "Generate a password of multiple dictionary \
                words chosen from the EFF word list. The len \
                parameter for this option will set the number \
                of words to generate, rather than characters."
        )]
        diceware: bool,
    },

    #[command(
        about = "Modify an existing password",
        long_about = "Modify an existing password\n\n\
            This command will open a text editor with the existing \
            password and notes of the given entry for editing. \
            The editor to use is determined  by the value of the \
            $VISUAL or $EDITOR environment variables. The first line \
            will be saved as the password and the remainder will be saved \
            as a note."
    )]
    Edit {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "Remove a given entry", visible_alias = "rm")]
    Remove {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(
        about = "View the password history for a given entry (oldest to current)"
    )]
    History {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            short = 'v',
            long,
            value_name = "VERSION",
            help = "Show only a specific version (e.g. 1, v1, or current)"
        )]
        version: Option<String>,
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
        #[cfg(feature = "clipboard")]
        #[arg(
            short,
            long,
            requires = "version",
            conflicts_with = "raw",
            help = "Copy the selected version's password to clipboard"
        )]
        clipboard: bool,
    },

    #[command(
        about = "Manage file attachments on vault entries",
        visible_alias = "attach"
    )]
    Attachment {
        #[command(subcommand)]
        action: AttachmentAction,
    },

    #[command(about = "Lock the password database")]
    Lock {
        #[arg(long, help = "Lock all configured accounts")]
        all: bool,
    },

    #[command(about = "Remove the local copy of the password database")]
    Purge,

    #[command(name = "stop-agent", about = "Terminate the background agent")]
    StopAgent,

    #[command(
        name = "gen-completions",
        about = "Generate completion script for the given shell"
    )]
    GenCompletions { shell: CompletionShell },

    #[cfg(feature = "mcp")]
    #[command(
        about = "Run the local MCP 2.0 server (stdio) or install its bundled agent skill"
    )]
    Mcp {
        #[arg(
            long,
            help = "Enable write and delete tools (vault_write, vault_delete, attachment upload) [env: RBW_MCP_ALLOW_WRITE]"
        )]
        allow_write: bool,
        #[arg(
            long = "allowed-dir",
            value_name = "DIR",
            help = "Allow attachment download/upload inside this directory (repeatable) [env: RBW_MCP_ALLOWED_DIRS]"
        )]
        allowed_dirs: Vec<std::path::PathBuf>,
        #[arg(
            long,
            default_value_t = 60,
            value_name = "SECS",
            help = "Timeout in seconds for out-of-band unlock via vault_session"
        )]
        unlock_timeout: u64,
        #[command(subcommand)]
        action: Option<McpAction>,
    },

    #[cfg(feature = "self-update")]
    #[command(name = "self", about = "Manage the rbw installation")]
    Self_ {
        #[command(subcommand)]
        action: SelfAction,
    },

    #[cfg(feature = "self-update")]
    #[command(
        name = "self-update",
        about = "Update rbw to the latest GitHub release (alias for `rbw self update`)"
    )]
    SelfUpdate(SelfUpdateArgs),
}

impl Opt {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Account { action } => {
                format!("account {}", action.subcommand_name())
            }
            Self::Switch { .. } => "switch".to_string(),
            Self::Config { config } => {
                format!("config {}", config.subcommand_name())
            }
            Self::Register => "register".to_string(),
            Self::Login { .. } => "login".to_string(),
            Self::Yubikey { action } => {
                format!("yubikey {}", action.subcommand_name())
            }
            Self::Unlock => "unlock".to_string(),
            Self::Unlocked => "unlocked".to_string(),
            Self::Sync => "sync".to_string(),
            Self::List { .. } => "list".to_string(),
            Self::Get { .. } => "get".to_string(),
            Self::Search { .. } => "search".to_string(),
            Self::Code { .. } => "code".to_string(),
            Self::Add { .. } => "add".to_string(),
            Self::Generate { .. } => "generate".to_string(),
            Self::Edit { .. } => "edit".to_string(),
            Self::Remove { .. } => "remove".to_string(),
            Self::History { .. } => "history".to_string(),
            Self::Attachment { action } => {
                format!("attachment {}", action.subcommand_name())
            }
            Self::Lock { .. } => "lock".to_string(),
            Self::Purge => "purge".to_string(),
            Self::StopAgent => "stop-agent".to_string(),
            Self::GenCompletions { .. } => "gen-completions".to_string(),
            #[cfg(feature = "mcp")]
            Self::Mcp { action, .. } => action.as_ref().map_or_else(
                || "mcp".to_string(),
                |action| format!("mcp {}", action.subcommand_name()),
            ),
            #[cfg(feature = "self-update")]
            Self::Self_ { action } => {
                format!("self {}", action.subcommand_name())
            }
            #[cfg(feature = "self-update")]
            Self::SelfUpdate(_) => "self-update".to_string(),
        }
    }
}

#[cfg(feature = "self-update")]
#[derive(Debug, clap::Args)]
struct SelfUpdateArgs {
    #[arg(
        long,
        help = "Check if a newer release is available without installing"
    )]
    check: bool,
    #[arg(
        long,
        value_name = "VERSION",
        help = "Install a specific release version (e.g. 1.16.0 or v1.16.0)"
    )]
    version: Option<String>,
    #[arg(
        long,
        help = "Reinstall even if already up to date or managed by a package manager"
    )]
    force: bool,
}

#[cfg(feature = "self-update")]
#[derive(Debug, clap::Subcommand)]
enum SelfAction {
    #[command(about = "Update rbw and rbw-agent from GitHub Releases")]
    Update(SelfUpdateArgs),
}

#[cfg(feature = "self-update")]
impl SelfAction {
    fn subcommand_name(&self) -> &'static str {
        match self {
            Self::Update(_) => "update",
        }
    }
}

#[cfg(feature = "mcp")]
#[derive(Debug, clap::Subcommand)]
enum McpAction {
    #[command(
        name = "install-skill",
        about = "Install the bundled rbw Agent Skill to local agent directories"
    )]
    InstallSkill {
        #[arg(
            long,
            value_enum,
            default_value_t = mcp::SkillTarget::Agents,
            conflicts_with = "dir",
            help = "Target agent runtime (agents, agy, omp, claude, all)"
        )]
        target: mcp::SkillTarget,
        #[arg(
            long,
            value_name = "PATH",
            conflicts_with = "target",
            help = "Install skill files directly into this directory"
        )]
        dir: Option<std::path::PathBuf>,
        #[arg(long, help = "Overwrite existing skill files")]
        force: bool,
    },
}

#[cfg(feature = "mcp")]
impl McpAction {
    fn subcommand_name(&self) -> &'static str {
        match self {
            Self::InstallSkill { .. } => "install-skill",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
    Nushell,
    Fig,
}

#[derive(Debug, clap::Subcommand)]
enum AccountAction {
    #[command(about = "Add a new Bitwarden / Vaultwarden account")]
    Add {
        #[arg(help = "Short name/alias for this account")]
        name: Option<String>,
        #[arg(long, help = "Account email address")]
        email: Option<String>,
        #[arg(
            long,
            visible_alias = "base-url",
            help = "Vault server (bitwarden.com, bitwarden.eu, or custom URL)"
        )]
        server: Option<String>,
        #[arg(long, help = "Custom identity server URL")]
        identity_url: Option<String>,
        #[arg(long, help = "Custom UI URL")]
        ui_url: Option<String>,
        #[arg(long, help = "Custom notifications server URL")]
        notifications_url: Option<String>,
        #[arg(long, help = "SSO organization ID")]
        sso_id: Option<String>,
        #[arg(long, help = "Path to client TLS certificate")]
        client_cert_path: Option<std::path::PathBuf>,
        #[arg(
            long,
            help = "Do not switch to the new account after adding it"
        )]
        no_switch: bool,
        #[arg(
            long,
            conflicts_with = "no_login",
            help = "Log in immediately after adding the account"
        )]
        login: bool,
        #[arg(
            long,
            conflicts_with = "login",
            help = "Do not prompt to log in after adding the account"
        )]
        no_login: bool,
        #[arg(
            long,
            conflicts_with = "no_login",
            help = "Log in using a FIDO2 passkey after adding the account"
        )]
        passkey: bool,
    },
    #[command(about = "Switch the active Bitwarden account")]
    Switch {
        #[arg(help = "Account name, email, server, or email@server")]
        account: Option<String>,
        #[arg(short = 'e', long, help = "Filter by account email address")]
        email: Option<String>,
        #[arg(
            short = 's',
            long,
            help = "Filter by vault server host or URL"
        )]
        server: Option<String>,
    },
    #[command(
        about = "List configured accounts and their lock status",
        visible_aliases = ["ls", "status"]
    )]
    List {
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
    },
    #[command(about = "Print the active account name")]
    Current,
    #[command(about = "Remove a configured account", visible_alias = "rm")]
    Remove {
        #[arg(help = "Account name, email, server, or email@server")]
        account: Option<String>,
        #[arg(
            long,
            help = "Keep local cached database, Touch ID, and YubiKey keys"
        )]
        keep_data: bool,
    },
    #[command(about = "Rename an account alias")]
    Rename {
        #[arg(help = "Current account name or selector")]
        old: String,
        #[arg(help = "New account name")]
        new: String,
    },
}

impl AccountAction {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Add { .. } => "add",
            Self::Switch { .. } => "switch",
            Self::List { .. } => "list",
            Self::Current => "current",
            Self::Remove { .. } => "remove",
            Self::Rename { .. } => "rename",
        }
        .to_string()
    }
}

#[derive(Debug, clap::Subcommand)]
enum Config {
    #[command(about = "Show the values of all configuration settings")]
    Show {
        #[arg(long, help = "Show global default settings")]
        global: bool,
    },
    #[command(about = "Set a configuration option")]
    Set {
        #[arg(
            long,
            help = "Set a global default instead of an account-specific override"
        )]
        global: bool,
        #[arg(help = "Configuration key to set")]
        key: String,
        #[arg(help = "Value to set the configuration option to")]
        value: String,
    },
    #[command(about = "Reset a configuration option to its default")]
    Unset {
        #[arg(
            long,
            help = "Reset a global default instead of an account-specific override"
        )]
        global: bool,
        #[arg(help = "Configuration key to unset")]
        key: String,
    },
}

impl Config {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Show { .. } => "show",
            Self::Set { .. } => "set",
            Self::Unset { .. } => "unset",
        }
        .to_string()
    }
}

#[derive(Debug, clap::Subcommand)]
enum YubikeyAction {
    #[command(
        about = "Enroll a connected FIDO2 security key for local vault unlock"
    )]
    Enroll {
        #[arg(long, help = "Optional label for this security key")]
        label: Option<String>,
    },
    #[command(about = "List enrolled security keys for local vault unlock")]
    List,
    #[command(
        about = "Remove an enrolled security key by label or ID prefix"
    )]
    Remove {
        #[arg(help = "Label or credential ID prefix of the key to remove")]
        key: String,
    },
    #[command(about = "Remove all enrolled security keys for this account")]
    Clear,
}

impl YubikeyAction {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Enroll { .. } => "enroll",
            Self::List => "list",
            Self::Remove { .. } => "remove",
            Self::Clear => "clear",
        }
        .to_string()
    }
}

#[derive(Debug, clap::Subcommand)]
enum AttachmentAction {
    #[command(
        about = "List attachments for a given entry",
        visible_alias = "ls"
    )]
    List {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(long, help = "Display output as JSON")]
        raw: bool,
    },
    #[command(
        about = "Upload a file attachment to a given entry",
        visible_alias = "add"
    )]
    Upload {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            short = 'f',
            long = "file",
            value_name = "PATH",
            help = "Path to the file to upload, or - to read from stdin"
        )]
        file: std::path::PathBuf,
        #[arg(
            long = "name",
            value_name = "FILENAME",
            help = "Override the attachment filename stored in the vault (required when reading from stdin)"
        )]
        file_name: Option<String>,
    },
    #[command(
        about = "Download an attachment from a given entry",
        visible_alias = "get"
    )]
    Download {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            short = 'A',
            long = "attachment",
            value_name = "NAME_OR_ID",
            help = "Exact filename or attachment ID to download"
        )]
        attachment: String,
        #[arg(
            short = 'o',
            long,
            value_name = "PATH",
            help = "Output file path, or - for binary stdout"
        )]
        output: std::path::PathBuf,
    },
    #[command(
        about = "Remove an attachment from a given entry",
        visible_alias = "rm"
    )]
    Remove {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            short = 'A',
            long = "attachment",
            value_name = "NAME_OR_ID",
            help = "Exact filename or attachment ID to remove"
        )]
        attachment: String,
    },
}

impl AttachmentAction {
    fn subcommand_name(&self) -> String {
        match self {
            Self::List { .. } => "list",
            Self::Upload { .. } => "upload",
            Self::Download { .. } => "download",
            Self::Remove { .. } => "remove",
        }
        .to_string()
    }
}

fn main() {
    let cli = Cli::parse();
    let env_account = std::env::var("RBW_ACCOUNT").ok();
    let account = cli
        .account
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| env_account.as_deref().filter(|s| !s.is_empty()));

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .format(|buf, record| {
        if let Some((terminal_size::Width(w), _)) =
            terminal_size::terminal_size()
        {
            let out = format!("{}: {}", record.level(), record.args());
            writeln!(buf, "{}", textwrap::fill(&out, usize::from(w) - 1))
        } else {
            writeln!(buf, "{}: {}", record.level(), record.args())
        }
    })
    .init();

    let subcommand_name = cli.command.subcommand_name();
    let res = match cli.command {
        Opt::Account { action } => match action {
            AccountAction::Add {
                name,
                email,
                server,
                identity_url,
                ui_url,
                notifications_url,
                sso_id,
                client_cert_path,
                no_switch,
                login,
                no_login,
                passkey,
            } => commands::account_add(commands::AccountAddOpts {
                name: name.as_deref(),
                email: email.as_deref(),
                server: server.as_deref(),
                identity_url: identity_url.as_deref(),
                ui_url: ui_url.as_deref(),
                notifications_url: notifications_url.as_deref(),
                sso_id: sso_id.as_deref(),
                client_cert_path: client_cert_path.as_deref(),
                no_switch,
                login,
                no_login,
                passkey,
            }),
            AccountAction::Switch {
                account: target,
                email,
                server,
            } => commands::account_switch(
                target.as_deref(),
                email.as_deref(),
                server.as_deref(),
            ),
            AccountAction::List { raw } => commands::account_list(raw),
            AccountAction::Current => commands::account_current(account),
            AccountAction::Remove {
                account: target,
                keep_data,
            } => commands::account_remove(target.as_deref(), keep_data),
            AccountAction::Rename { old, new } => {
                commands::account_rename(&old, &new)
            }
        },
        Opt::Switch {
            account: target,
            email,
            server,
        } => commands::account_switch(
            target.as_deref(),
            email.as_deref(),
            server.as_deref(),
        ),
        Opt::Config { config } => match config {
            Config::Show { global } => commands::config_show(account, global),
            Config::Set { global, key, value } => {
                commands::config_set(account, global, &key, &value)
            }
            Config::Unset { global, key } => {
                commands::config_unset(account, global, &key)
            }
        },
        Opt::Register => commands::register(account),
        Opt::Login { passkey, password } => {
            commands::login(account, passkey, password)
        }
        Opt::Yubikey { action } => match action {
            YubikeyAction::Enroll { label } => {
                commands::yubikey_enroll(account, label.as_deref())
            }
            YubikeyAction::List => commands::yubikey_list(account),
            YubikeyAction::Remove { key } => {
                commands::yubikey_remove(account, &key)
            }
            YubikeyAction::Clear => commands::yubikey_clear(account),
        },
        Opt::Unlock => commands::unlock(account),
        Opt::Unlocked => commands::unlocked(account),
        Opt::Sync => commands::sync(account),
        Opt::List { fields, raw } => commands::list(account, &fields, raw),
        Opt::Get {
            find_args,
            field,
            full,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            list_fields,
            attachment,
            output,
        } => commands::get(
            account,
            find_args.needle.clone(),
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            field.as_deref(),
            full,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
            list_fields,
            attachment.as_deref(),
            output.as_deref(),
        ),
        Opt::Search {
            term,
            fields,
            folder,
            raw,
        } => {
            commands::search(account, &term, &fields, folder.as_deref(), raw)
        }
        Opt::Code {
            find_args,
            #[cfg(feature = "clipboard")]
            clipboard,
        } => commands::code(
            account,
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
        ),
        Opt::Add {
            name,
            user,
            uri,
            folder,
            entry_type,
            note,
        } => {
            let entry_type = if note {
                commands::AddEntryType::Note
            } else {
                entry_type.unwrap_or_default()
            };
            commands::add(
                account,
                &name,
                user.as_deref(),
                &uri.iter()
                    // XXX not sure what the ui for specifying the match type
                    // should be
                    .map(|uri| (uri.clone(), None))
                    .collect::<Vec<_>>(),
                folder.as_deref(),
                entry_type,
            )
        }
        Opt::Generate {
            len,
            name,
            user,
            uri,
            folder,
            no_symbols,
            only_numbers,
            nonconfusables,
            diceware,
        } => {
            let ty = if no_symbols {
                rbw::pwgen::Type::NoSymbols
            } else if only_numbers {
                rbw::pwgen::Type::Numbers
            } else if nonconfusables {
                rbw::pwgen::Type::NonConfusables
            } else if diceware {
                rbw::pwgen::Type::Diceware
            } else {
                rbw::pwgen::Type::AllChars
            };
            commands::generate(
                account,
                name.as_deref(),
                user.as_deref(),
                &uri.iter()
                    // XXX not sure what the ui for specifying the match type
                    // should be
                    .map(|uri| (uri.clone(), None))
                    .collect::<Vec<_>>(),
                folder.as_deref(),
                len,
                ty,
            )
        }
        Opt::Edit { find_args } => commands::edit(
            account,
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::Remove { find_args } => commands::remove(
            account,
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::History {
            find_args,
            version,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
        } => commands::history(
            account,
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
            version.as_deref(),
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
        ),
        Opt::Attachment { action } => match action {
            AttachmentAction::List { find_args, raw } => {
                commands::attachment_list(
                    account,
                    find_args.needle,
                    find_args.user.as_deref(),
                    find_args.folder.as_deref(),
                    find_args.ignorecase,
                    raw,
                )
            }
            AttachmentAction::Upload {
                find_args,
                file,
                file_name,
            } => commands::attachment_upload(
                account,
                find_args.needle,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.ignorecase,
                &file,
                file_name.as_deref(),
            ),
            AttachmentAction::Download {
                find_args,
                attachment,
                output,
            } => commands::attachment_download(
                account,
                find_args.needle,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.ignorecase,
                &attachment,
                &output,
            ),
            AttachmentAction::Remove {
                find_args,
                attachment,
            } => commands::attachment_remove(
                account,
                find_args.needle,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.ignorecase,
                &attachment,
            ),
        },
        Opt::Lock { all } => commands::lock(account, all),
        Opt::Purge => commands::purge(account),
        Opt::StopAgent => commands::stop_agent(),
        Opt::GenCompletions { shell } => {
            match shell {
                CompletionShell::Bash => {
                    clap_complete::generate(
                        clap_complete::Shell::Bash,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.bash"));
                }
                CompletionShell::Fish => {
                    clap_complete::generate(
                        clap_complete::Shell::Fish,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.fish"));
                }
                CompletionShell::Zsh => {
                    clap_complete::generate(
                        clap_complete::Shell::Zsh,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.zsh"));
                }
                CompletionShell::Powershell => {
                    clap_complete::generate(
                        clap_complete::Shell::PowerShell,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Elvish => {
                    clap_complete::generate(
                        clap_complete::Shell::Elvish,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Nushell => {
                    clap_complete::generate(
                        clap_complete_nushell::Nushell,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Fig => {
                    clap_complete::generate(
                        clap_complete_fig::Fig,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
            }
            Ok(())
        }
        #[cfg(feature = "mcp")]
        Opt::Mcp {
            allow_write,
            mut allowed_dirs,
            unlock_timeout,
            action,
        } => match action {
            Some(McpAction::InstallSkill { target, dir, force }) => {
                mcp::install_skill(target, dir.as_deref(), force)
            }
            None => {
                let env_allow_write = std::env::var("RBW_MCP_ALLOW_WRITE")
                    .is_ok_and(|v| {
                        matches!(
                            v.trim().to_ascii_lowercase().as_str(),
                            "1" | "true" | "yes"
                        )
                    });
                if let Ok(env_dirs) = std::env::var("RBW_MCP_ALLOWED_DIRS") {
                    for part in env_dirs.split(',') {
                        let trimmed = part.trim();
                        if !trimmed.is_empty() {
                            allowed_dirs
                                .push(std::path::PathBuf::from(trimmed));
                        }
                    }
                }
                mcp::serve(mcp::McpServeOpts {
                    account: account.map(str::to_string),
                    allow_write: allow_write || env_allow_write,
                    allowed_dirs,
                    unlock_timeout_secs: unlock_timeout,
                })
            }
        },
        #[cfg(feature = "self-update")]
        Opt::Self_ {
            action: SelfAction::Update(args),
        }
        | Opt::SelfUpdate(args) => {
            self_update::run(&self_update::UpdateOpts {
                check: args.check,
                version: args.version,
                force: args.force,
            })
        }
    }
    .with_context(|| format!("rbw {subcommand_name}"));

    if let Err(e) = res {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_global_account_and_account_subcommands() {
        let cli = Cli::try_parse_from(["rbw", "-a", "work", "ls"]).unwrap();
        assert_eq!(cli.account.as_deref(), Some("work"));
        assert!(matches!(cli.command, Opt::List { .. }));

        let cli =
            Cli::try_parse_from(["rbw", "get", "github", "--account", "bw"])
                .unwrap();
        assert_eq!(cli.account.as_deref(), Some("bw"));
        assert!(matches!(cli.command, Opt::Get { .. }));

        let cli = Cli::try_parse_from(["rbw", "switch", "nullbyte"]).unwrap();
        assert!(matches!(
            cli.command,
            Opt::Switch {
                account: Some(ref a),
                email: None,
                server: None,
            } if a == "nullbyte"
        ));

        let cli = Cli::try_parse_from(["rbw", "account", "status", "--raw"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Opt::Account {
                action: AccountAction::List { raw: true }
            }
        ));

        let cli = Cli::try_parse_from([
            "rbw",
            "account",
            "add",
            "work",
            "--email",
            "user@example.com",
            "--server",
            "https://vault.example.com",
            "--no-switch",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Opt::Account {
                action: AccountAction::Add {
                    name: Some(ref n),
                    email: Some(ref e),
                    server: Some(ref s),
                    no_switch: true,
                    ..
                }
            } if n == "work" && e == "user@example.com" && s == "https://vault.example.com"
        ));

        let cli = Cli::try_parse_from(["rbw", "lock", "--all"]).unwrap();
        assert!(matches!(cli.command, Opt::Lock { all: true }));

        let cli = Cli::try_parse_from([
            "rbw",
            "config",
            "set",
            "--global",
            "lock_timeout",
            "1800",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Opt::Config {
                config: Config::Set {
                    global: true,
                    ref key,
                    ref value,
                }
            } if key == "lock_timeout" && value == "1800"
        ));
    }

    #[test]
    fn test_cli_history_secure_note_and_attachments() {
        Cli::command().debug_assert();

        // PR #389 attachment flags on `rbw get`
        for option in ["--raw", "--full", "--list-fields"] {
            assert!(
                Cli::try_parse_from([
                    "rbw",
                    "get",
                    "entry",
                    "--attachment",
                    "file",
                    "--output",
                    "out",
                    option,
                ])
                .is_err()
            );
        }
        assert!(
            Cli::try_parse_from([
                "rbw",
                "get",
                "entry",
                "--attachment",
                "file"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from(["rbw", "get", "entry", "--output", "out"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "rbw",
                "get",
                "entry",
                "user",
                "--folder",
                "folder",
                "--ignorecase",
                "--attachment",
                "file",
                "--output",
                "-",
            ])
            .is_ok()
        );
        #[cfg(feature = "clipboard")]
        assert!(
            Cli::try_parse_from([
                "rbw",
                "get",
                "entry",
                "--attachment",
                "file",
                "--output",
                "out",
                "--clipboard",
            ])
            .is_err()
        );

        // History flags
        let cli = Cli::try_parse_from([
            "rbw",
            "history",
            "github",
            "--version",
            "1",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Opt::History {
                version: Some(ref v),
                raw: false,
                ..
            } if v == "1"
        ));
        assert!(
            Cli::try_parse_from(["rbw", "history", "github", "--raw"])
                .is_ok()
        );
        #[cfg(feature = "clipboard")]
        {
            assert!(
                Cli::try_parse_from(["rbw", "history", "github", "-c"])
                    .is_err()
            );
            assert!(
                Cli::try_parse_from([
                    "rbw", "history", "github", "-v", "current", "-c",
                ])
                .is_ok()
            );
            assert!(
                Cli::try_parse_from([
                    "rbw", "history", "github", "-v", "1", "-c", "--raw",
                ])
                .is_err()
            );
        }

        // SecureNote add flags
        let cli = Cli::try_parse_from([
            "rbw", "add", "--note", "My Note", "--folder", "personal",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Opt::Add {
                ref name,
                note: true,
                entry_type: None,
                folder: Some(ref f),
                ..
            } if name == "My Note" && f == "personal"
        ));
        assert!(
            Cli::try_parse_from([
                "rbw",
                "add",
                "--type",
                "secure-note",
                "My Note",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["rbw", "add", "--note", "My Note", "user"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "rbw",
                "add",
                "--note",
                "My Note",
                "--uri",
                "https://example.com",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "rbw", "add", "--note", "--type", "login", "My Note",
            ])
            .is_err()
        );

        // Attachment subcommands
        assert!(
            Cli::try_parse_from([
                "rbw",
                "attachment",
                "upload",
                "entry",
                "--file",
                "./secret.pdf",
                "--name",
                "renamed.pdf",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["rbw", "attach", "ls", "entry", "--raw"])
                .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "rbw",
                "attachment",
                "download",
                "entry",
                "--attachment",
                "secret.pdf",
                "--output",
                "./out.pdf",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "rbw",
                "attachment",
                "rm",
                "entry",
                "-A",
                "secret.pdf",
            ])
            .is_ok()
        );

        #[cfg(feature = "mcp")]
        {
            let cli = Cli::try_parse_from(["rbw", "mcp"]).unwrap();
            assert!(matches!(
                cli.command,
                Opt::Mcp {
                    allow_write: false,
                    ref allowed_dirs,
                    unlock_timeout: 60,
                    action: None,
                } if allowed_dirs.is_empty()
            ));

            let cli = Cli::try_parse_from([
                "rbw",
                "-a",
                "work",
                "mcp",
                "--allow-write",
                "--allowed-dir",
                "/tmp/a",
                "--allowed-dir",
                "/tmp/b",
                "--unlock-timeout",
                "90",
            ])
            .unwrap();
            assert_eq!(cli.account.as_deref(), Some("work"));
            assert!(matches!(
                cli.command,
                Opt::Mcp {
                    allow_write: true,
                    ref allowed_dirs,
                    unlock_timeout: 90,
                    action: None,
                } if allowed_dirs.len() == 2
            ));

            let cli = Cli::try_parse_from([
                "rbw",
                "mcp",
                "install-skill",
                "--target",
                "agy",
                "--force",
            ])
            .unwrap();
            assert!(matches!(
                cli.command,
                Opt::Mcp {
                    action: Some(McpAction::InstallSkill {
                        target: mcp::SkillTarget::Agy,
                        dir: None,
                        force: true,
                    }),
                    ..
                }
            ));

            assert!(
                Cli::try_parse_from([
                    "rbw",
                    "mcp",
                    "install-skill",
                    "--target",
                    "omp",
                    "--dir",
                    "/tmp/custom",
                ])
                .is_err()
            );
        }

        #[cfg(feature = "self-update")]
        {
            let cli = Cli::try_parse_from(["rbw", "self", "update"]).unwrap();
            assert!(matches!(
                cli.command,
                Opt::Self_ {
                    action: SelfAction::Update(SelfUpdateArgs {
                        check: false,
                        version: None,
                        force: false,
                    })
                }
            ));

            let cli = Cli::try_parse_from([
                "rbw",
                "self",
                "update",
                "--check",
                "--version",
                "v1.16.0",
                "--force",
            ])
            .unwrap();
            assert!(matches!(
                cli.command,
                Opt::Self_ {
                    action: SelfAction::Update(SelfUpdateArgs {
                        check: true,
                        version: Some(ref v),
                        force: true,
                    })
                } if v == "v1.16.0"
            ));

            let cli = Cli::try_parse_from([
                "rbw",
                "self-update",
                "--version",
                "1.16.0",
            ])
            .unwrap();
            assert!(matches!(
                cli.command,
                Opt::SelfUpdate(SelfUpdateArgs {
                    check: false,
                    version: Some(ref v),
                    force: false,
                }) if v == "1.16.0"
            ));
        }
    }
}
