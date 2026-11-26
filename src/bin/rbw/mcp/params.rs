use rmcp::schemars::{self, JsonSchema};
use serde::Deserialize;

use crate::commands::mcp_ops;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntryTypeParam {
    Login,
    Note,
    Card,
    Identity,
    SshKey,
}

impl From<EntryTypeParam> for mcp_ops::EntryKind {
    fn from(value: EntryTypeParam) -> Self {
        match value {
            EntryTypeParam::Login => Self::Login,
            EntryTypeParam::Note => Self::Note,
            EntryTypeParam::Card => Self::Card,
            EntryTypeParam::Identity => Self::Identity,
            EntryTypeParam::SshKey => Self::SshKey,
        }
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PasswordStyleParam {
    #[default]
    AllChars,
    NoSymbols,
    Numbers,
    Nonconfusables,
    Diceware,
}

impl PasswordStyleParam {
    pub fn into_pwgen_type(self) -> rbw::pwgen::Type {
        match self {
            Self::AllChars => rbw::pwgen::Type::AllChars,
            Self::NoSymbols => rbw::pwgen::Type::NoSymbols,
            Self::Numbers => rbw::pwgen::Type::Numbers,
            Self::Nonconfusables => rbw::pwgen::Type::NonConfusables,
            Self::Diceware => rbw::pwgen::Type::Diceware,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllChars => "all_chars",
            Self::NoSymbols => "no_symbols",
            Self::Numbers => "numbers",
            Self::Nonconfusables => "nonconfusables",
            Self::Diceware => "diceware",
        }
    }

    pub fn resolve_length(
        self,
        requested: Option<usize>,
    ) -> anyhow::Result<usize> {
        if self == Self::Diceware {
            let len = requested.unwrap_or(5);
            if !(1..=32).contains(&len) {
                anyhow::bail!(
                    "diceware word count must be between 1 and 32 (got {len})"
                );
            }
            Ok(len)
        } else {
            let len = requested.unwrap_or(20);
            if !(1..=256).contains(&len) {
                anyhow::bail!(
                    "password length must be between 1 and 256 (got {len})"
                );
            }
            Ok(len)
        }
    }
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct VaultStatusParams {
    /// Optional account alias, email, or server to inspect (defaults to active account)
    pub account: Option<String>,
    /// Include decrypted folder names for the target account (requires unlocked vault)
    #[serde(default)]
    pub include_folders: bool,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct VaultSearchParams {
    /// Case-insensitive search query across name, username, URIs, notes, and non-hidden fields
    pub query: Option<String>,
    /// URL or hostname matched using each entry's Bitwarden URI match rule
    pub url: Option<String>,
    /// Filter by folder name (case-insensitive)
    pub folder: Option<String>,
    /// Filter by entry type
    pub entry_type: Option<EntryTypeParam>,
    /// Maximum number of entries to return (default 50, max 200)
    pub limit: Option<usize>,
    /// Pagination offset (default 0)
    pub offset: Option<usize>,
    /// Optional account alias, email, or server override
    pub account: Option<String>,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GetMode {
    #[default]
    Summary,
    Field,
    Totp,
    History,
    Full,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VaultGetParams {
    /// Entry UUID (preferred), name, or URL
    pub query: String,
    /// Retrieval mode: summary (metadata only, default), field, totp, history, or full
    #[serde(default)]
    pub mode: GetMode,
    /// Field name when `mode='field'` (e.g. `password`, `username`, `totp`, `totp_secret`, `notes`, `private_key`, or custom field)
    pub field: Option<String>,
    /// Password history version selector when `mode='history'` (e.g. `1`, `v1`, or `current`)
    pub version: Option<String>,
    /// Optional username to disambiguate duplicate entry names
    pub username: Option<String>,
    /// Optional folder name to disambiguate duplicate entry names
    pub folder: Option<String>,
    /// Case-insensitive name/user/folder matching
    #[serde(default)]
    pub ignore_case: bool,
    /// Copy the retrieved secret/TOTP directly to OS clipboard via `rbw-agent` without returning plaintext
    #[serde(default)]
    pub copy_to_clipboard: bool,
    /// Optional account alias, email, or server override
    pub account: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct VaultGenerateParams {
    /// Password character length (default 20, max 256) or word count for diceware (default 5, max 32)
    pub length: Option<usize>,
    /// Character set or passphrase style (default: `all_chars`)
    #[serde(default)]
    pub style: PasswordStyleParam,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionAction {
    Unlock,
    Lock,
    Sync,
    SwitchAccount,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VaultSessionParams {
    /// Session action: `unlock` (out-of-band Touch ID/YubiKey/pinentry), `lock`, `sync`, or `switch_account`
    pub action: SessionAction,
    /// Optional account alias, email, or server override (for unlock, lock, sync)
    pub account: Option<String>,
    /// When `action='lock'`, lock all configured accounts
    #[serde(default)]
    pub all: bool,
    /// Target account alias, email, server, or `email@server` for `action='switch_account'`
    pub target: Option<String>,
    /// Filter by email for `action='switch_account'`
    pub email: Option<String>,
    /// Filter by vault server host or URL for `action='switch_account'`
    pub server: Option<String>,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CustomFieldTypeParam {
    #[default]
    Text,
    Hidden,
    Boolean,
}

impl From<CustomFieldTypeParam> for rbw::api::FieldType {
    fn from(value: CustomFieldTypeParam) -> Self {
        match value {
            CustomFieldTypeParam::Text => Self::Text,
            CustomFieldTypeParam::Hidden => Self::Hidden,
            CustomFieldTypeParam::Boolean => Self::Boolean,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CustomFieldParam {
    pub name: String,
    pub value: String,
    #[serde(default, rename = "type")]
    pub field_type: CustomFieldTypeParam,
}

impl From<CustomFieldParam> for mcp_ops::CustomFieldInput {
    fn from(value: CustomFieldParam) -> Self {
        Self {
            name: value.name,
            value: value.value,
            field_type: value.field_type.into(),
        }
    }
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct LoginParam {
    pub username: Option<String>,
    pub password: Option<String>,
    /// TOTP seed or `otpauth://` URI (pass empty string on `update_item` to clear)
    pub totp: Option<String>,
    pub uris: Option<Vec<String>>,
}

impl From<LoginParam> for mcp_ops::LoginInput {
    fn from(value: LoginParam) -> Self {
        Self {
            username: value.username,
            password: value.password,
            totp: value.totp,
            uris: value.uris,
        }
    }
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct CardParam {
    pub cardholder_name: Option<String>,
    pub number: Option<String>,
    pub brand: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
}

impl From<CardParam> for mcp_ops::CardInput {
    fn from(value: CardParam) -> Self {
        Self {
            cardholder_name: value.cardholder_name,
            number: value.number,
            brand: value.brand,
            exp_month: value.exp_month,
            exp_year: value.exp_year,
            code: value.code,
        }
    }
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct IdentityParam {
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub ssn: Option<String>,
    pub license_number: Option<String>,
    pub passport_number: Option<String>,
    pub username: Option<String>,
}

impl From<IdentityParam> for mcp_ops::IdentityInput {
    fn from(value: IdentityParam) -> Self {
        Self {
            title: value.title,
            first_name: value.first_name,
            middle_name: value.middle_name,
            last_name: value.last_name,
            address1: value.address1,
            address2: value.address2,
            address3: value.address3,
            city: value.city,
            state: value.state,
            postal_code: value.postal_code,
            country: value.country,
            phone: value.phone,
            email: value.email,
            ssn: value.ssn,
            license_number: value.license_number,
            passport_number: value.passport_number,
            username: value.username,
        }
    }
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct GeneratePasswordSpec {
    /// Password length (default 20) or word count for diceware (default 5)
    pub length: Option<usize>,
    /// Character set or passphrase style (default: `all_chars`)
    #[serde(default)]
    pub style: PasswordStyleParam,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WriteAction {
    CreateItem,
    UpdateItem,
    CreateFolder,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VaultWriteParams {
    /// Write action: `create_item`, `update_item`, or `create_folder`
    pub action: WriteAction,
    /// Optional account alias, email, or server override
    pub account: Option<String>,
    /// Entry type for `action='create_item'` (`login`, `note`, `card`, `identity`; default: `login`)
    pub entry_type: Option<EntryTypeParam>,
    /// Entry or folder name (required for `create_item` and `create_folder`; optional rename for `update_item`)
    pub name: Option<String>,
    /// Target entry UUID (preferred), name, or URL for `action='update_item'`
    pub query: Option<String>,
    /// Optional username to disambiguate target entry for `action='update_item'`
    pub match_username: Option<String>,
    /// Optional folder to disambiguate target entry for `action='update_item'`
    pub match_folder: Option<String>,
    /// Case-insensitive matching for `action='update_item'`
    #[serde(default)]
    pub ignore_case: bool,
    /// Folder name to place the entry in (created automatically if missing)
    pub folder: Option<String>,
    /// Set true on `action='update_item'` to remove the entry from its folder
    #[serde(default)]
    pub clear_folder: bool,
    /// Notes text (pass empty string on `update_item` to clear)
    pub notes: Option<String>,
    /// Custom fields (replaces all custom fields when provided on `update_item`)
    pub fields: Option<Vec<CustomFieldParam>>,
    /// Login payload for login items
    pub login: Option<LoginParam>,
    /// Card payload for card items
    pub card: Option<CardParam>,
    /// Identity payload for identity items
    pub identity: Option<IdentityParam>,
    /// Generate and store a random password server-side for login items (without echoing plaintext)
    pub generate_password: Option<GeneratePasswordSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeleteTarget {
    Item,
    Attachment,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VaultDeleteParams {
    /// Target to permanently delete: item or attachment
    pub target: DeleteTarget,
    /// Entry UUID (preferred), name, or URL
    pub query: String,
    /// Attachment ID (preferred) or exact filename when target='attachment'
    pub attachment: Option<String>,
    /// Optional username to disambiguate duplicate entry names
    pub username: Option<String>,
    /// Optional folder name to disambiguate duplicate entry names
    pub folder: Option<String>,
    /// Case-insensitive entry matching
    #[serde(default)]
    pub ignore_case: bool,
    /// Optional account alias, email, or server override
    pub account: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentAction {
    Download,
    Upload,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VaultAttachmentParams {
    /// Attachment transfer action: download or upload (upload also requires --allow-write)
    pub action: AttachmentAction,
    /// Entry UUID (preferred), name, or URL
    pub query: String,
    /// Local file path strictly inside a configured --allowed-dir
    pub path: String,
    /// Attachment ID (preferred) or exact filename when action='download'
    pub attachment: Option<String>,
    /// Optional stored filename override when action='upload'
    pub file_name: Option<String>,
    /// Optional username to disambiguate duplicate entry names
    pub username: Option<String>,
    /// Optional folder name to disambiguate duplicate entry names
    pub folder: Option<String>,
    /// Case-insensitive entry matching
    #[serde(default)]
    pub ignore_case: bool,
    /// Optional account alias, email, or server override
    pub account: Option<String>,
}
