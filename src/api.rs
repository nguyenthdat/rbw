// serde_repr generates some as conversions that we can't seem to silence from
// here, unfortunately
#![allow(clippy::as_conversions)]

use crate::prelude::*;

use rand::distr::SampleString as _;
use sha2::Digest as _;
use tokio::io::AsyncReadExt as _;

use crate::json::{
    DeserializeJsonWithPath as _, DeserializeJsonWithPathAsync as _,
};

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
)]
#[repr(u8)]
pub enum UriMatchType {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}

impl std::fmt::Display for UriMatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[allow(clippy::enum_glob_use)]
        use UriMatchType::*;
        let s = match self {
            Domain => "domain",
            Host => "host",
            StartsWith => "starts_with",
            Exact => "exact",
            RegularExpression => "regular_expression",
            Never => "never",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TwoFactorProviderType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    Yubikey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}

impl TwoFactorProviderType {
    pub fn message(&self) -> &str {
        match *self {
            Self::Authenticator => {
                "Enter the 6 digit verification code from your authenticator app."
            }
            Self::Yubikey => "Insert your Yubikey and push the button.",
            Self::Email => "Enter the PIN you received via email.",
            Self::WebAuthn => "Insert and touch your FIDO2 security key.",
            _ => "Enter the code.",
        }
    }

    pub fn header(&self) -> &str {
        match *self {
            Self::Authenticator => "Authenticator App",
            Self::Yubikey => "Yubikey",
            Self::Email => "Email Code",
            Self::WebAuthn => "Security Key (WebAuthn)",
            _ => "Two Factor Authentication",
        }
    }

    pub fn grab(&self) -> bool {
        !matches!(self, Self::Email)
    }
}

impl<'de> serde::Deserialize<'de> for TwoFactorProviderType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TwoFactorProviderTypeVisitor;
        impl serde::de::Visitor<'_> for TwoFactorProviderTypeVisitor {
            type Value = TwoFactorProviderType;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("two factor provider id")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                std::convert::TryFrom::try_from(value)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(TwoFactorProviderTypeVisitor)
    }
}

impl std::convert::TryFrom<u64> for TwoFactorProviderType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Authenticator),
            1 => Ok(Self::Email),
            2 => Ok(Self::Duo),
            3 => Ok(Self::Yubikey),
            4 => Ok(Self::U2f),
            5 => Ok(Self::Remember),
            6 => Ok(Self::OrganizationDuo),
            7 => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl std::str::FromStr for TwoFactorProviderType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Authenticator),
            "1" => Ok(Self::Email),
            "2" => Ok(Self::Duo),
            "3" => Ok(Self::Yubikey),
            "4" => Ok(Self::U2f),
            "5" => Ok(Self::Remember),
            "6" => Ok(Self::OrganizationDuo),
            "7" => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider { ty: ty.to_string() }),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}

impl<'de> serde::Deserialize<'de> for KdfType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KdfTypeVisitor;
        impl serde::de::Visitor<'_> for KdfTypeVisitor {
            type Value = KdfType;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("kdf id")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                std::convert::TryFrom::try_from(value)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(KdfTypeVisitor)
    }
}

impl std::convert::TryFrom<u64> for KdfType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Pbkdf2),
            1 => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl std::str::FromStr for KdfType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Pbkdf2),
            "1" => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType { ty: ty.to_string() }),
        }
    }
}

impl serde::Serialize for KdfType {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            Self::Pbkdf2 => "0",
            Self::Argon2id => "1",
        };
        serializer.serialize_str(s)
    }
}

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
)]
#[repr(u8)]
pub enum CipherRepromptType {
    None = 0,
    Password = 1,
}

#[derive(serde::Serialize, Debug)]
struct PreloginReq {
    email: String,
}

#[derive(serde::Deserialize, Debug)]
struct PreloginRes {
    #[serde(rename = "Kdf", alias = "kdf")]
    kdf: KdfType,
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    kdf_iterations: u32,
    #[serde(rename = "KdfMemory", alias = "kdfMemory")]
    kdf_memory: Option<u32>,
    #[serde(rename = "KdfParallelism", alias = "kdfParallelism")]
    kdf_parallelism: Option<u32>,
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenReq {
    grant_type: String,
    scope: String,
    client_id: String,
    #[serde(rename = "deviceType")]
    device_type: u32,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: String,
    #[serde(rename = "deviceName")]
    device_name: String,
    #[serde(rename = "devicePushToken")]
    device_push_token: String,
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,
    #[serde(rename = "twoFactorProvider")]
    two_factor_provider: Option<u32>,
    #[serde(flatten)]
    auth: ConnectTokenAuth,
}

#[derive(serde::Serialize, Debug)]
#[serde(untagged)]
enum ConnectTokenAuth {
    Password(ConnectTokenPassword),
    AuthCode(ConnectTokenAuthCode),
    ClientCredentials(ConnectTokenClientCredentials),
    WebAuthn(ConnectTokenWebAuthn),
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenPassword {
    username: String,
    password: String,
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenAuthCode {
    code: String,
    code_verifier: String,
    redirect_uri: String,
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenClientCredentials {
    username: String,
    client_secret: String,
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenWebAuthn {
    token: String,
    #[serde(rename = "deviceResponse")]
    device_response: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnAssertionOptions {
    pub challenge: String,
    #[serde(alias = "rpId", alias = "RpId")]
    pub rp_id: Option<String>,
    #[serde(default, alias = "AllowCredentials")]
    pub allow_credentials: Vec<WebAuthnCredentialDescriptor>,
    #[serde(alias = "UserVerification")]
    pub user_verification: Option<String>,
    #[serde(alias = "Timeout")]
    pub timeout: Option<u64>,
    #[serde(alias = "Extensions")]
    pub extensions: Option<WebAuthnRequestExtensions>,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct WebAuthnCredentialDescriptor {
    #[serde(alias = "Id")]
    pub id: String,
    #[serde(rename = "type", alias = "Type")]
    pub ty: Option<String>,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct WebAuthnRequestExtensions {
    #[serde(alias = "AppID", alias = "appId")]
    pub appid: Option<String>,
}

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnLoginAssertionOptionsRes {
    #[serde(alias = "Options")]
    pub options: WebAuthnAssertionOptions,
    #[serde(alias = "Token")]
    pub token: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct WebAuthnPrfOption {
    #[serde(rename = "EncryptedPrivateKey", alias = "encryptedPrivateKey")]
    pub encrypted_private_key: String,
    #[serde(rename = "EncryptedUserKey", alias = "encryptedUserKey")]
    pub encrypted_user_key: String,
    #[serde(rename = "CredentialId", alias = "credentialId")]
    pub credential_id: Option<String>,
}

#[derive(serde::Deserialize, Debug, Clone)]
struct UserDecryptionOptions {
    #[serde(rename = "WebAuthnPrfOption", alias = "webAuthnPrfOption")]
    webauthn_prf_option: Option<WebAuthnPrfOption>,
}

#[derive(Debug, Clone)]
pub struct WebAuthnLoginRes {
    pub access_token: String,
    pub refresh_token: String,
    pub key: Option<String>,
    pub kdf: Option<KdfType>,
    pub kdf_iterations: Option<u32>,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
    pub webauthn_prf_option: Option<WebAuthnPrfOption>,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectTokenRes {
    access_token: String,
    refresh_token: String,
    #[serde(rename = "Key", alias = "key")]
    key: Option<String>,
    #[serde(rename = "Kdf", alias = "kdf")]
    kdf: Option<KdfType>,
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    kdf_iterations: Option<u32>,
    #[serde(rename = "KdfMemory", alias = "kdfMemory")]
    kdf_memory: Option<u32>,
    #[serde(rename = "KdfParallelism", alias = "kdfParallelism")]
    kdf_parallelism: Option<u32>,
    #[serde(
        rename = "UserDecryptionOptions",
        alias = "userDecryptionOptions"
    )]
    user_decryption_options: Option<UserDecryptionOptions>,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectErrorRes {
    error: String,
    error_description: Option<String>,
    #[serde(rename = "ErrorModel", alias = "errorModel")]
    error_model: Option<ConnectErrorResErrorModel>,
    #[serde(rename = "TwoFactorProviders", alias = "twoFactorProviders")]
    two_factor_providers: Option<Vec<TwoFactorProviderType>>,
    #[serde(rename = "TwoFactorProviders2", alias = "twoFactorProviders2")]
    two_factor_providers2:
        Option<std::collections::HashMap<String, serde_json::Value>>,
    #[serde(
        rename = "SsoEmail2faSessionToken",
        alias = "ssoEmail2faSessionToken"
    )]
    sso_email_2fa_session_token: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectErrorResErrorModel {
    #[serde(rename = "Message", alias = "message")]
    message: String,
}

#[derive(serde::Serialize, Debug)]
struct ConnectRefreshTokenReq {
    grant_type: String,
    client_id: String,
    refresh_token: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectRefreshTokenRes {
    access_token: String,
}

#[derive(serde::Serialize, Debug)]
struct SendEmailLoginReq {
    email: String,
    #[serde(rename = "DeviceIdentifier", alias = "deviceIdentifier")]
    device_identifier: String,
    #[serde(
        rename = "SsoEmail2faSessionToken",
        alias = "ssoEmail2faSessionToken"
    )]
    sso_email_2fa_session_token: String,
}

#[derive(serde::Deserialize, Debug)]
struct SyncRes {
    #[serde(rename = "Ciphers", alias = "ciphers")]
    ciphers: Vec<SyncResCipher>,
    #[serde(rename = "Profile", alias = "profile")]
    profile: SyncResProfile,
    #[serde(rename = "Folders", alias = "folders")]
    folders: Vec<SyncResFolder>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct SyncResCipher {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "FolderId", alias = "folderId")]
    folder_id: Option<String>,
    #[serde(rename = "OrganizationId", alias = "organizationId")]
    organization_id: Option<String>,
    #[serde(rename = "Name", alias = "name")]
    name: String,
    #[serde(rename = "Login", alias = "login")]
    login: Option<CipherLogin>,
    #[serde(rename = "Card", alias = "card")]
    card: Option<CipherCard>,
    #[serde(rename = "Identity", alias = "identity")]
    identity: Option<CipherIdentity>,
    #[serde(rename = "SecureNote", alias = "secureNote")]
    secure_note: Option<CipherSecureNote>,
    #[serde(rename = "SshKey", alias = "sshKey")]
    ssh_key: Option<CipherSshKey>,
    #[serde(rename = "Notes", alias = "notes")]
    notes: Option<String>,
    #[serde(rename = "PasswordHistory", alias = "passwordHistory")]
    password_history: Option<Vec<SyncResPasswordHistory>>,
    #[serde(rename = "Fields", alias = "fields")]
    fields: Option<Vec<CipherField>>,
    #[serde(rename = "DeletedDate", alias = "deletedDate")]
    deleted_date: Option<String>,
    #[serde(rename = "Key", alias = "key")]
    key: Option<String>,
    #[serde(rename = "Attachments", alias = "attachments")]
    attachments: Option<Vec<crate::attachment::Attachment>>,
    #[serde(rename = "RevisionDate", alias = "revisionDate")]
    revision_date: Option<String>,
    #[serde(rename = "Reprompt", alias = "reprompt")]
    reprompt: CipherRepromptType,
}

impl SyncResCipher {
    fn to_entry(
        &self,
        folders: &[SyncResFolder],
    ) -> Option<crate::db::Entry> {
        if self.deleted_date.is_some() {
            return None;
        }
        let history =
            self.password_history
                .as_ref()
                .map_or_else(Vec::new, |history| {
                    history
                        .iter()
                        .filter_map(|entry| {
                            // Gets rid of entries with a non-existent
                            // password
                            entry.password.clone().map(|p| {
                                crate::db::HistoryEntry {
                                    last_used_date: entry
                                        .last_used_date
                                        .clone(),
                                    password: p,
                                }
                            })
                        })
                        .collect()
                });

        let (folder, folder_id) =
            self.folder_id.as_ref().map_or((None, None), |folder_id| {
                let mut folder_name = None;
                for folder in folders {
                    if &folder.id == folder_id {
                        folder_name = Some(folder.name.clone());
                    }
                }
                (folder_name, Some(folder_id))
            });
        let data = if let Some(login) = &self.login {
            crate::db::EntryData::Login {
                username: login.username.clone(),
                password: login.password.clone(),
                totp: login.totp.clone(),
                uris: login.uris.as_ref().map_or_else(
                    std::vec::Vec::new,
                    |uris| {
                        uris.iter()
                            .filter_map(|uri| {
                                uri.uri.clone().map(|s| crate::db::Uri {
                                    uri: s,
                                    match_type: uri.match_type,
                                })
                            })
                            .collect()
                    },
                ),
                password_revision_date: login.password_revision_date.clone(),
            }
        } else if let Some(card) = &self.card {
            crate::db::EntryData::Card {
                cardholder_name: card.cardholder_name.clone(),
                number: card.number.clone(),
                brand: card.brand.clone(),
                exp_month: card.exp_month.clone(),
                exp_year: card.exp_year.clone(),
                code: card.code.clone(),
            }
        } else if let Some(identity) = &self.identity {
            crate::db::EntryData::Identity {
                title: identity.title.clone(),
                first_name: identity.first_name.clone(),
                middle_name: identity.middle_name.clone(),
                last_name: identity.last_name.clone(),
                address1: identity.address1.clone(),
                address2: identity.address2.clone(),
                address3: identity.address3.clone(),
                city: identity.city.clone(),
                state: identity.state.clone(),
                postal_code: identity.postal_code.clone(),
                country: identity.country.clone(),
                phone: identity.phone.clone(),
                email: identity.email.clone(),
                ssn: identity.ssn.clone(),
                license_number: identity.license_number.clone(),
                passport_number: identity.passport_number.clone(),
                username: identity.username.clone(),
            }
        } else if let Some(_secure_note) = &self.secure_note {
            crate::db::EntryData::SecureNote
        } else if let Some(ssh_key) = &self.ssh_key {
            crate::db::EntryData::SshKey {
                private_key: ssh_key.private_key.clone(),
                public_key: ssh_key.public_key.clone(),
                fingerprint: ssh_key.fingerprint.clone(),
            }
        } else {
            return None;
        };
        let fields = self.fields.as_ref().map_or_else(Vec::new, |fields| {
            fields
                .iter()
                .map(|field| crate::db::Field {
                    ty: field.ty,
                    name: field.name.clone(),
                    value: field.value.clone(),
                    linked_id: field.linked_id,
                })
                .collect()
        });
        Some(crate::db::Entry {
            id: self.id.clone(),
            org_id: self.organization_id.clone(),
            folder,
            folder_id: folder_id.map(std::string::ToString::to_string),
            name: self.name.clone(),
            data,
            fields,
            notes: self.notes.clone(),
            history,
            key: self.key.clone(),
            attachments: self.attachments.clone().unwrap_or_default(),
            revision_date: self.revision_date.clone(),
            master_password_reprompt: self.reprompt,
        })
    }
}

#[derive(serde::Deserialize, Debug)]
struct SyncResProfile {
    #[serde(rename = "Key", alias = "key")]
    key: String,
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    private_key: String,
    #[serde(rename = "Organizations", alias = "organizations")]
    organizations: Vec<SyncResProfileOrganization>,
}

#[derive(serde::Deserialize, Debug)]
struct SyncResProfileOrganization {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Key", alias = "key")]
    key: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
struct SyncResFolder {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Name", alias = "name")]
    name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherLogin {
    #[serde(rename = "Username", alias = "username")]
    username: Option<String>,
    #[serde(rename = "Password", alias = "password")]
    password: Option<String>,
    #[serde(rename = "Totp", alias = "totp")]
    totp: Option<String>,
    #[serde(rename = "Uris", alias = "uris")]
    uris: Option<Vec<CipherLoginUri>>,
    #[serde(
        rename = "PasswordRevisionDate",
        alias = "passwordRevisionDate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    password_revision_date: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherLoginUri {
    #[serde(rename = "Uri", alias = "uri")]
    uri: Option<String>,
    #[serde(rename = "Match", alias = "match")]
    match_type: Option<UriMatchType>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherCard {
    #[serde(rename = "CardholderName", alias = "cardholderName")]
    cardholder_name: Option<String>,
    #[serde(rename = "Number", alias = "number")]
    number: Option<String>,
    #[serde(rename = "Brand", alias = "brand")]
    brand: Option<String>,
    #[serde(rename = "ExpMonth", alias = "expMonth")]
    exp_month: Option<String>,
    #[serde(rename = "ExpYear", alias = "expYear")]
    exp_year: Option<String>,
    #[serde(rename = "Code", alias = "code")]
    code: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherIdentity {
    #[serde(rename = "Title", alias = "title")]
    title: Option<String>,
    #[serde(rename = "FirstName", alias = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "MiddleName", alias = "middleName")]
    middle_name: Option<String>,
    #[serde(rename = "LastName", alias = "lastName")]
    last_name: Option<String>,
    #[serde(rename = "Address1", alias = "address1")]
    address1: Option<String>,
    #[serde(rename = "Address2", alias = "address2")]
    address2: Option<String>,
    #[serde(rename = "Address3", alias = "address3")]
    address3: Option<String>,
    #[serde(rename = "City", alias = "city")]
    city: Option<String>,
    #[serde(rename = "State", alias = "state")]
    state: Option<String>,
    #[serde(rename = "PostalCode", alias = "postalCode")]
    postal_code: Option<String>,
    #[serde(rename = "Country", alias = "country")]
    country: Option<String>,
    #[serde(rename = "Phone", alias = "phone")]
    phone: Option<String>,
    #[serde(rename = "Email", alias = "email")]
    email: Option<String>,
    #[serde(rename = "SSN", alias = "ssn")]
    ssn: Option<String>,
    #[serde(rename = "LicenseNumber", alias = "licenseNumber")]
    license_number: Option<String>,
    #[serde(rename = "PassportNumber", alias = "passportNumber")]
    passport_number: Option<String>,
    #[serde(rename = "Username", alias = "username")]
    username: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherSshKey {
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    private_key: Option<String>,
    #[serde(rename = "PublicKey", alias = "publicKey")]
    public_key: Option<String>,
    #[serde(rename = "Fingerprint", alias = "keyFingerprint")]
    fingerprint: Option<String>,
}

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
)]
#[repr(u16)]
pub enum FieldType {
    Text = 0,
    Hidden = 1,
    Boolean = 2,
    Linked = 3,
}

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
)]
#[repr(u16)]
pub enum LinkedIdType {
    LoginUsername = 100,
    LoginPassword = 101,
    CardCardholderName = 300,
    CardExpMonth = 301,
    CardExpYear = 302,
    CardCode = 303,
    CardBrand = 304,
    CardNumber = 305,
    IdentityTitle = 400,
    IdentityMiddleName = 401,
    IdentityAddress1 = 402,
    IdentityAddress2 = 403,
    IdentityAddress3 = 404,
    IdentityCity = 405,
    IdentityState = 406,
    IdentityPostalCode = 407,
    IdentityCountry = 408,
    IdentityCompany = 409,
    IdentityEmail = 410,
    IdentityPhone = 411,
    IdentitySsn = 412,
    IdentityUsername = 413,
    IdentityPassportNumber = 414,
    IdentityLicenseNumber = 415,
    IdentityFirstName = 416,
    IdentityLastName = 417,
    IdentityFullName = 418,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherField {
    #[serde(rename = "Type", alias = "type")]
    ty: Option<FieldType>,
    #[serde(rename = "Name", alias = "name")]
    name: Option<String>,
    #[serde(rename = "Value", alias = "value")]
    value: Option<String>,
    #[serde(rename = "LinkedId", alias = "linkedId")]
    linked_id: Option<LinkedIdType>,
}

// Generic secure note subtype is 0 in Bitwarden/Vaultwarden APIs.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
struct CipherSecureNote {
    #[serde(rename = "type", alias = "Type", default)]
    ty: u32,
}

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
)]
#[repr(u8)]
pub enum FileUploadType {
    Direct = 0,
    Azure = 1,
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AttachmentV2Req {
    file_name: String,
    file_size: u64,
    key: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct AttachmentUploadData {
    #[serde(rename = "AttachmentId", alias = "attachmentId")]
    pub attachment_id: String,
    #[serde(rename = "Url", alias = "url", default)]
    pub url: String,
    #[serde(rename = "FileUploadType", alias = "fileUploadType")]
    pub file_upload_type: FileUploadType,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct SyncResPasswordHistory {
    #[serde(rename = "LastUsedDate", alias = "lastUsedDate")]
    last_used_date: String,
    #[serde(rename = "Password", alias = "password")]
    password: Option<String>,
}

#[derive(serde::Serialize, Debug)]
struct CiphersPostReq {
    #[serde(rename = "type")]
    ty: u32, // XXX what are the valid types?
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    name: String,
    notes: Option<String>,
    login: Option<CipherLogin>,
    card: Option<CipherCard>,
    identity: Option<CipherIdentity>,
    #[serde(rename = "secureNote")]
    secure_note: Option<CipherSecureNote>,
}

#[derive(serde::Serialize, Debug)]
struct CiphersPutReq {
    #[serde(rename = "type")]
    ty: u32, // XXX what are the valid types?
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
    name: String,
    notes: Option<String>,
    login: Option<CipherLogin>,
    card: Option<CipherCard>,
    identity: Option<CipherIdentity>,
    fields: Vec<CipherField>,
    #[serde(rename = "secureNote")]
    secure_note: Option<CipherSecureNote>,
    #[serde(rename = "passwordHistory")]
    password_history: Vec<CiphersPutReqHistory>,
}

#[derive(serde::Serialize, Debug)]
struct CiphersPutReqHistory {
    #[serde(rename = "LastUsedDate")]
    last_used_date: String,
    #[serde(rename = "Password")]
    password: String,
}

#[derive(serde::Deserialize, Debug)]
struct FoldersRes {
    #[serde(rename = "Data", alias = "data")]
    data: Vec<FoldersResData>,
}

#[derive(serde::Deserialize, Debug)]
struct FoldersResData {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Name", alias = "name")]
    name: String,
}

#[derive(serde::Serialize, Debug)]
struct FoldersPostReq {
    name: String,
}

// Used for the Bitwarden-Client-Name header. Accepted values:
// https://github.com/bitwarden/server/blob/main/src/Core/Enums/BitwardenClient.cs
const BITWARDEN_CLIENT: &str = "cli";

// DeviceType.LinuxDesktop, as per Bitwarden API device types.
const DEVICE_TYPE: u8 = 8;

#[derive(Debug)]
pub struct Client {
    base_url: String,
    identity_url: String,
    ui_url: String,
    client_cert_path: Option<std::path::PathBuf>,
}

impl Client {
    pub fn new(
        base_url: &str,
        identity_url: &str,
        ui_url: &str,
        client_cert_path: Option<&std::path::Path>,
    ) -> Self {
        Self {
            base_url: base_url.to_string(),
            identity_url: identity_url.to_string(),
            ui_url: ui_url.to_string(),
            client_cert_path: client_cert_path
                .map(std::path::Path::to_path_buf),
        }
    }

    async fn reqwest_client(&self) -> Result<reqwest::Client> {
        self.reqwest_client_with_redirect(reqwest::redirect::Policy::default())
            .await
    }

    async fn reqwest_client_with_redirect(
        &self,
        redirect: reqwest::redirect::Policy,
    ) -> Result<reqwest::Client> {
        let mut default_headers = axum::http::HeaderMap::new();
        default_headers.insert(
            "Bitwarden-Client-Name",
            axum::http::HeaderValue::from_static(BITWARDEN_CLIENT),
        );
        default_headers.insert(
            "Bitwarden-Client-Version",
            axum::http::HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
        );
        default_headers.append(
            "Device-Type",
            // unwrap is safe here because DEVICE_TYPE is a number and digits
            // are valid ASCII
            axum::http::HeaderValue::from_str(&DEVICE_TYPE.to_string())
                .unwrap(),
        );
        let user_agent = format!(
            "{}/{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
        if let Some(client_cert_path) = self.client_cert_path.as_ref() {
            let mut buf = Vec::new();
            let mut f = tokio::fs::File::open(client_cert_path)
                .await
                .map_err(|e| Error::LoadClientCert {
                    source: e,
                    file: client_cert_path.clone(),
                })?;
            f.read_to_end(&mut buf).await.map_err(|e| {
                Error::LoadClientCert {
                    source: e,
                    file: client_cert_path.clone(),
                }
            })?;
            let pem = reqwest::Identity::from_pem(&buf)
                .map_err(|e| Error::CreateReqwestClient { source: e })?;
            Ok(reqwest::Client::builder()
                .user_agent(user_agent)
                .identity(pem)
                .redirect(redirect)
                .default_headers(default_headers)
                .build()
                .map_err(|e| Error::CreateReqwestClient { source: e })?)
        } else {
            Ok(reqwest::Client::builder()
                .user_agent(user_agent)
                .redirect(redirect)
                .default_headers(default_headers)
                .build()
                .map_err(|e| Error::CreateReqwestClient { source: e })?)
        }
    }

    pub async fn prelogin(
        &self,
        email: &str,
    ) -> Result<(KdfType, u32, Option<u32>, Option<u32>)> {
        let prelogin = PreloginReq {
            email: email.to_string(),
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/accounts/prelogin"))
            .json(&prelogin)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        let prelogin_res: PreloginRes = res.json_with_path().await?;
        Ok((
            prelogin_res.kdf,
            prelogin_res.kdf_iterations,
            prelogin_res.kdf_memory,
            prelogin_res.kdf_parallelism,
        ))
    }

    pub async fn register(
        &self,
        email: &str,
        device_id: &str,
        apikey: &crate::locked::ApiKey,
    ) -> Result<()> {
        let connect_req = ConnectTokenReq {
            auth: ConnectTokenAuth::ClientCredentials(
                ConnectTokenClientCredentials {
                    username: email.to_string(),
                    client_secret: String::from_utf8(
                        apikey.client_secret().to_vec(),
                    )
                    .unwrap(),
                },
            ),
            grant_type: "client_credentials".to_string(),
            scope: "api".to_string(),
            // XXX unwraps here are not necessarily safe
            client_id: String::from_utf8(apikey.client_id().to_vec())
                .unwrap(),
            device_type: u32::from(DEVICE_TYPE),
            device_identifier: device_id.to_string(),
            device_name: "rbw".to_string(),
            device_push_token: String::new(),
            two_factor_token: None,
            two_factor_provider: None,
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        if res.status() == reqwest::StatusCode::OK {
            Ok(())
        } else {
            let code = res.status().as_u16();
            match res.text().await {
                Ok(body) => match body.clone().json_with_path() {
                    Ok(json) => Err(classify_login_error(&json, code)),
                    Err(e) => {
                        log::warn!("{e}: {body}");
                        Err(Error::RequestFailed { status: code })
                    }
                },
                Err(e) => {
                    log::warn!("failed to read response body: {e}");
                    Err(Error::RequestFailed { status: code })
                }
            }
        }
    }

    pub async fn login(
        &self,
        email: &str,
        sso_id: Option<&str>,
        device_id: &str,
        password_hash: &crate::locked::PasswordHash,
        two_factor_token: Option<&str>,
        two_factor_provider: Option<TwoFactorProviderType>,
    ) -> Result<(String, String, String)> {
        let connect_req = match sso_id {
            Some(sso_id) => {
                let (sso_code, sso_code_verifier, callback_url) =
                    self.obtain_sso_code(sso_id).await?;

                ConnectTokenReq {
                    auth: ConnectTokenAuth::AuthCode(ConnectTokenAuthCode {
                        code: sso_code,
                        code_verifier: sso_code_verifier,
                        redirect_uri: callback_url,
                    }),
                    grant_type: "authorization_code".to_string(),
                    scope: "api offline_access".to_string(),
                    client_id: "cli".to_string(),
                    device_type: u32::from(DEVICE_TYPE),
                    device_identifier: device_id.to_string(),
                    device_name: "rbw".to_string(),
                    device_push_token: String::new(),
                    two_factor_token: two_factor_token
                        .map(std::string::ToString::to_string),
                    two_factor_provider: two_factor_provider
                        .map(|ty| ty as u32),
                }
            }
            None => ConnectTokenReq {
                auth: ConnectTokenAuth::Password(ConnectTokenPassword {
                    username: email.to_string(),
                    password: crate::base64::encode(password_hash.hash()),
                }),

                grant_type: "password".to_string(),
                scope: "api offline_access".to_string(),
                client_id: "cli".to_string(),
                device_type: 8,
                device_identifier: device_id.to_string(),
                device_name: "rbw".to_string(),
                device_push_token: String::new(),
                two_factor_token: two_factor_token
                    .map(std::string::ToString::to_string),
                two_factor_provider: two_factor_provider.map(|ty| ty as u32),
            },
        };

        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .header(
                "auth-email",
                crate::base64::encode_url_safe_no_pad(email),
            )
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;

        if res.status() == reqwest::StatusCode::OK {
            let connect_res: ConnectTokenRes = res.json_with_path().await?;
            let key = connect_res.key.ok_or_else(|| Error::Fido2 {
                message:
                    "server login response did not include protected key"
                        .to_string(),
            })?;
            Ok((connect_res.access_token, connect_res.refresh_token, key))
        } else {
            let code = res.status().as_u16();
            match res.text().await {
                Ok(body) => match body.clone().json_with_path() {
                    Ok(json) => Err(classify_login_error(&json, code)),
                    Err(e) => {
                        log::warn!("{e}: {body}");
                        Err(Error::RequestFailed { status: code })
                    }
                },
                Err(e) => {
                    log::warn!("failed to read response body: {e}");
                    Err(Error::RequestFailed { status: code })
                }
            }
        }
    }

    pub async fn webauthn_login_assertion_options(
        &self,
    ) -> Result<WebAuthnLoginAssertionOptionsRes> {
        let client = self.reqwest_client().await?;
        let res = client
            .get(self.identity_url("/accounts/webauthn/assertion-options"))
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => res.json_with_path().await,
            reqwest::StatusCode::NOT_FOUND
            | reqwest::StatusCode::METHOD_NOT_ALLOWED => {
                Err(Error::PasskeyLoginUnsupported {
                    status: res.status().as_u16(),
                })
            }
            status => {
                let code = status.as_u16();
                log::warn!("{code}: {:?}", res.text().await);
                Err(Error::RequestFailed { status: code })
            }
        }
    }

    pub async fn login_webauthn(
        &self,
        device_id: &str,
        token: &str,
        device_response: &str,
    ) -> Result<WebAuthnLoginRes> {
        let connect_req = ConnectTokenReq {
            auth: ConnectTokenAuth::WebAuthn(ConnectTokenWebAuthn {
                token: token.to_string(),
                device_response: device_response.to_string(),
            }),
            grant_type: "webauthn".to_string(),
            scope: "api offline_access".to_string(),
            client_id: "cli".to_string(),
            device_type: u32::from(DEVICE_TYPE),
            device_identifier: device_id.to_string(),
            device_name: "rbw".to_string(),
            device_push_token: String::new(),
            two_factor_token: None,
            two_factor_provider: None,
        };

        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;

        if res.status() == reqwest::StatusCode::OK {
            let connect_res: ConnectTokenRes = res.json_with_path().await?;
            Ok(WebAuthnLoginRes {
                access_token: connect_res.access_token,
                refresh_token: connect_res.refresh_token,
                key: connect_res.key,
                kdf: connect_res.kdf,
                kdf_iterations: connect_res.kdf_iterations,
                kdf_memory: connect_res.kdf_memory,
                kdf_parallelism: connect_res.kdf_parallelism,
                webauthn_prf_option: connect_res
                    .user_decryption_options
                    .and_then(|o| o.webauthn_prf_option),
            })
        } else {
            let code = res.status().as_u16();
            match res.text().await {
                Ok(body) => match body.clone().json_with_path() {
                    Ok(json) => Err(classify_login_error(&json, code)),
                    Err(e) => {
                        log::warn!("{e}: {body}");
                        Err(Error::RequestFailed { status: code })
                    }
                },
                Err(e) => {
                    log::warn!("failed to read response body: {e}");
                    Err(Error::RequestFailed { status: code })
                }
            }
        }
    }

    pub async fn send_email_login(
        &self,
        email: &str,
        device_id: &str,
        sso_email_2fa_session_token: &str,
    ) -> Result<()> {
        let send_email_login_req = SendEmailLoginReq {
            email: email.to_string(),
            device_identifier: device_id.to_string(),
            sso_email_2fa_session_token: sso_email_2fa_session_token
                .to_string(),
        };

        let client = self.reqwest_client().await?;
        let res = client
            .post(self.api_url("/two-factor/send-email-login"))
            .json(&send_email_login_req)
            .header(
                "auth-email",
                crate::base64::encode_url_safe_no_pad(email),
            )
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;

        if res.status() == reqwest::StatusCode::OK {
            Ok(())
        } else {
            let code = res.status().as_u16();
            log::warn!("{code}: {:?}", res.text().await);
            Err(Error::RequestFailed { status: code })
        }
    }

    async fn obtain_sso_code(
        &self,
        sso_id: &str,
    ) -> Result<(String, String, String)> {
        let state =
            rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 64);
        let sso_code_verifier =
            rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 64);

        let mut hasher = sha2::Sha256::new();
        hasher.update(sso_code_verifier.clone());
        let code_challenge =
            crate::base64::encode_url_safe_no_pad(hasher.finalize());

        let port = find_free_port(8065, 8070).await?;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|e| Error::CreateSSOCallbackServer { err: e })?;

        let callback_server =
            start_sso_callback_server(listener, state.as_str());

        let callback_url =
            "http://localhost:".to_string() + port.to_string().as_str();

        open::that(
            self.ui_url.clone()
                + "/#/sso?clientId="
                + "cli"
                + "&redirectUri="
                + urlencoding::encode(callback_url.as_str())
                    .into_owned()
                    .as_str()
                + "&state="
                + state.as_str()
                + "&codeChallenge="
                + code_challenge.as_str()
                + "&identifier="
                + sso_id,
        )
        .map_err(|e| Error::FailedToOpenWebBrowser { err: e })?;
        // TODO: probably it'd be better to display the URL in the console if the automatic
        // open operation fails, instead of failing the whole process? E.g. docker container
        // case

        let sso_code = callback_server.await?;

        Ok((sso_code, sso_code_verifier, callback_url))
    }

    pub async fn sync(
        &self,
        access_token: &str,
    ) -> Result<(
        String,
        String,
        std::collections::HashMap<String, String>,
        Vec<crate::db::Entry>,
    )> {
        let client = self.reqwest_client().await?;
        let res = client
            .get(self.api_url("/sync"))
            .header("Authorization", format!("Bearer {access_token}"))
            // This is necessary for vaultwarden to include the ssh keys in the response
            .header("Bitwarden-Client-Version", "2024.12.0")
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let sync_res: SyncRes = res.json_with_path().await?;
                let folders = sync_res.folders.clone();
                let ciphers = sync_res
                    .ciphers
                    .iter()
                    .filter_map(|cipher| cipher.to_entry(&folders))
                    .collect();
                let org_keys = sync_res
                    .profile
                    .organizations
                    .iter()
                    .map(|org| (org.id.clone(), org.key.clone()))
                    .collect();
                Ok((
                    sync_res.profile.key,
                    sync_res.profile.private_key,
                    org_keys,
                    ciphers,
                ))
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    /// Fetch fresh cipher metadata from the server, rather than trusting the
    /// editable local cache for ownership, encryption keys, or reprompt state.
    pub async fn get_cipher(
        &self,
        access_token: &str,
        entry_id: &str,
    ) -> Result<crate::db::Entry> {
        validate_path_id(entry_id)?;
        let entry_path = encode_path_segment(entry_id);
        let client = self.reqwest_client().await?;
        let res = client
            .get(self.api_url(&format!("/ciphers/{entry_path}")))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::UNAUTHORIZED => {
                return Err(Error::RequestUnauthorized);
            }
            status => {
                return Err(Error::RequestFailed {
                    status: status.as_u16(),
                });
            }
        }
        let cipher: SyncResCipher = res.json_with_path().await?;
        let entry =
            cipher
                .to_entry(&[])
                .ok_or_else(|| Error::InvalidAttachment {
                    reason: "entry is deleted or unsupported".to_string(),
                })?;
        if entry.id != entry_id {
            return Err(Error::InvalidAttachment {
                reason: "server returned a different entry".to_string(),
            });
        }
        Ok(entry)
    }

    /// Fetch attachment metadata from the server, rather than trusting the
    /// editable local cache for the owning entry, encryption keys or reprompt.
    pub async fn attachment(
        &self,
        access_token: &str,
        entry_id: &str,
        attachment_id: &str,
    ) -> Result<(crate::db::Entry, crate::attachment::Attachment)> {
        validate_path_id(entry_id)?;
        validate_path_id(attachment_id)?;
        let entry = self.get_cipher(access_token, entry_id).await?;
        let mut matches =
            entry.attachments.iter().filter(|a| a.id == attachment_id);
        let mut attachment = matches.next().cloned().ok_or_else(|| {
            Error::InvalidAttachment {
                reason: "attachment not found in this entry".to_string(),
            }
        })?;
        if matches.next().is_some() {
            return Err(Error::InvalidAttachment {
                reason: "ambiguous attachment ID".to_string(),
            });
        }

        let entry_path = encode_path_segment(entry_id);
        let attachment_path = encode_path_segment(attachment_id);
        let client = self.reqwest_client().await?;
        // The URL in /sync may have expired. Modern servers issue a fresh
        // download URL here. Only a 404 permits the legacy metadata fallback.
        let res = client
            .get(self.api_url(&format!(
                "/ciphers/{entry_path}/attachment/{attachment_path}"
            )))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let fresh: crate::attachment::Attachment =
                    res.json_with_path().await?;
                if fresh.id != attachment_id {
                    return Err(Error::InvalidAttachment {
                        reason: "server returned a different attachment"
                            .to_string(),
                    });
                }
                attachment.url = fresh.url;
            }
            reqwest::StatusCode::NOT_FOUND => {}
            reqwest::StatusCode::UNAUTHORIZED => {
                return Err(Error::RequestUnauthorized);
            }
            status => {
                return Err(Error::RequestFailed {
                    status: status.as_u16(),
                });
            }
        }
        Ok((entry, attachment))
    }

    /// Fetch only the encrypted blob. Never forward a vault access token to
    /// the attachment host, including when it is the same host as the API.
    pub async fn attachment_bytes(
        &self,
        attachment: &crate::attachment::Attachment,
    ) -> Result<Vec<u8>> {
        let mut url = reqwest::Url::parse(&attachment.url).map_err(|_| {
            Error::InvalidAttachment {
                reason: "invalid download URL".to_string(),
            }
        })?;
        let base = reqwest::Url::parse(&self.base_url).map_err(|_| {
            Error::InvalidAttachment {
                reason: "invalid server URL".to_string(),
            }
        })?;
        for _ in 0..10 {
            validate_blob_url(&url, &base, "unsupported download URL")?;
            // Handle redirects here so client certificates are used only for
            // the configured API origin. No request carries a vault bearer.
            let client = if url.origin() == base.origin() {
                self.reqwest_client_with_redirect(
                    reqwest::redirect::Policy::none(),
                )
                .await?
            } else {
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|source| Error::CreateReqwestClient { source })?
            };
            let res =
                client.get(url.clone()).send().await.map_err(|source| {
                    Error::Reqwest {
                        source: source.without_url(),
                    }
                })?;
            if res.status().is_redirection() {
                let location = res
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| Error::InvalidAttachment {
                        reason: "download redirect has no valid location"
                            .to_string(),
                    })?;
                url = url.join(location).map_err(|_| {
                    Error::InvalidAttachment {
                        reason: "invalid download redirect".to_string(),
                    }
                })?;
                continue;
            }
            if res.status() != reqwest::StatusCode::OK {
                return Err(Error::RequestFailed {
                    status: res.status().as_u16(),
                });
            }
            return Ok(res
                .bytes()
                .await
                .map_err(|source| Error::Reqwest {
                    source: source.without_url(),
                })?
                .to_vec());
        }
        Err(Error::InvalidAttachment {
            reason: "too many download redirects".to_string(),
        })
    }

    /// Reserve a v2 attachment upload slot (`POST /ciphers/{id}/attachment/v2`).
    /// Returns `Ok(None)` if the server responds with 404 (legacy server).
    pub async fn upload_attachment_v2_metadata(
        &self,
        access_token: &str,
        entry_id: &str,
        encrypted_file_name: &str,
        encrypted_size: u64,
        encrypted_key: &str,
    ) -> Result<Option<AttachmentUploadData>> {
        validate_path_id(entry_id)?;
        let entry_path = encode_path_segment(entry_id);
        let req = AttachmentV2Req {
            file_name: encrypted_file_name.to_string(),
            file_size: encrypted_size,
            key: encrypted_key.to_string(),
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(
                self.api_url(&format!("/ciphers/{entry_path}/attachment/v2")),
            )
            .bearer_auth(access_token)
            .json(&req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK | reqwest::StatusCode::CREATED => {
                let data: AttachmentUploadData = res.json_with_path().await?;
                validate_path_id(&data.attachment_id)?;
                Ok(Some(data))
            }
            reqwest::StatusCode::NOT_FOUND => Ok(None),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            status => {
                let code = status.as_u16();
                if let Ok(body) = res.text().await {
                    log::warn!(
                        "attachment v2 metadata failed ({code}): {body}"
                    );
                }
                Err(Error::RequestFailed { status: code })
            }
        }
    }

    /// Upload encrypted bytes to a Direct (self-hosted / Vaultwarden) endpoint.
    pub async fn upload_attachment_direct(
        &self,
        access_token: &str,
        entry_id: &str,
        attachment_id: &str,
        upload_url: &str,
        encrypted_file_name: &str,
        encrypted_data: &[u8],
    ) -> Result<()> {
        validate_path_id(entry_id)?;
        validate_path_id(attachment_id)?;
        let target_url = self.resolve_direct_upload_url(
            entry_id,
            attachment_id,
            upload_url,
        )?;
        let (boundary, body) = build_multipart_form(
            &[],
            "data",
            encrypted_file_name,
            encrypted_data,
        );
        let client = self
            .reqwest_client_with_redirect(reqwest::redirect::Policy::none())
            .await?;
        let res = client
            .post(target_url)
            .bearer_auth(access_token)
            .header(
                reqwest::header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body)
            .send()
            .await
            .map_err(|source| Error::Reqwest {
                source: source.without_url(),
            })?;
        if res.status().is_success() {
            Ok(())
        } else if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(Error::RequestUnauthorized)
        } else {
            let code = res.status().as_u16();
            if let Ok(body) = res.text().await {
                log::warn!(
                    "direct attachment upload failed ({code}): {body}"
                );
            }
            Err(Error::RequestFailed { status: code })
        }
    }

    /// Upload encrypted bytes directly to an Azure Blob SAS URL without any
    /// vault bearer token or client certificate.
    pub async fn upload_attachment_azure(
        &self,
        upload_url: &str,
        encrypted_data: &[u8],
    ) -> Result<()> {
        const MAX_SINGLE_BLOB_UPLOAD_SIZE: usize = 256 * 1024 * 1024;

        let url = reqwest::Url::parse(upload_url).map_err(|_| {
            Error::InvalidAttachment {
                reason: "invalid upload URL".to_string(),
            }
        })?;
        let base = reqwest::Url::parse(&self.base_url).map_err(|_| {
            Error::InvalidAttachment {
                reason: "invalid server URL".to_string(),
            }
        })?;
        validate_blob_url(&url, &base, "unsupported upload URL")?;

        let ms_version = url
            .query_pairs()
            .find_map(|(k, v)| (k == "sv").then(|| v.into_owned()));
        let ms_date = format_http_date(std::time::SystemTime::now());
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|source| Error::CreateReqwestClient { source })?;

        if encrypted_data.len() <= MAX_SINGLE_BLOB_UPLOAD_SIZE {
            let mut req = client
                .put(url)
                .header("x-ms-date", &ms_date)
                .header("x-ms-blob-type", "BlockBlob")
                .header(
                    reqwest::header::CONTENT_LENGTH,
                    encrypted_data.len().to_string(),
                )
                .body(encrypted_data.to_vec());
            if let Some(version) = &ms_version {
                req = req.header("x-ms-version", version);
            }
            let res = req.send().await.map_err(|source| Error::Reqwest {
                source: source.without_url(),
            })?;
            if res.status() == reqwest::StatusCode::CREATED
                || res.status() == reqwest::StatusCode::OK
            {
                return Ok(());
            }
            return Err(Error::RequestFailed {
                status: res.status().as_u16(),
            });
        }

        // Single-block Put Block + Put Block List for blobs > 256 MiB
        let block_id = crate::base64::encode(format!("{:048}", 0));
        let mut block_url = url.clone();
        block_url
            .query_pairs_mut()
            .append_pair("comp", "block")
            .append_pair("blockid", &block_id);
        let mut block_req = client
            .put(block_url)
            .header("x-ms-date", &ms_date)
            .header(
                reqwest::header::CONTENT_LENGTH,
                encrypted_data.len().to_string(),
            )
            .body(encrypted_data.to_vec());
        if let Some(version) = &ms_version {
            block_req = block_req.header("x-ms-version", version);
        }
        let block_res =
            block_req.send().await.map_err(|source| Error::Reqwest {
                source: source.without_url(),
            })?;
        if block_res.status() != reqwest::StatusCode::CREATED
            && block_res.status() != reqwest::StatusCode::OK
        {
            return Err(Error::RequestFailed {
                status: block_res.status().as_u16(),
            });
        }

        let block_list_xml = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList><Latest>{block_id}</Latest></BlockList>"
        );
        let mut block_list_url = url;
        block_list_url
            .query_pairs_mut()
            .append_pair("comp", "blocklist");
        let mut list_req = client
            .put(block_list_url)
            .header("x-ms-date", &ms_date)
            .header(reqwest::header::CONTENT_TYPE, "application/xml")
            .header(
                reqwest::header::CONTENT_LENGTH,
                block_list_xml.len().to_string(),
            )
            .body(block_list_xml);
        if let Some(version) = &ms_version {
            list_req = list_req.header("x-ms-version", version);
        }
        let list_res =
            list_req.send().await.map_err(|source| Error::Reqwest {
                source: source.without_url(),
            })?;
        if list_res.status() == reqwest::StatusCode::CREATED
            || list_res.status() == reqwest::StatusCode::OK
        {
            Ok(())
        } else {
            Err(Error::RequestFailed {
                status: list_res.status().as_u16(),
            })
        }
    }

    /// Legacy single-request attachment upload (`POST /ciphers/{id}/attachment`)
    /// used only if `/attachment/v2` returns 404.
    pub async fn upload_attachment_legacy(
        &self,
        access_token: &str,
        entry_id: &str,
        encrypted_file_name: &str,
        encrypted_key: &str,
        encrypted_data: &[u8],
    ) -> Result<String> {
        validate_path_id(entry_id)?;
        let entry_path = encode_path_segment(entry_id);
        let (boundary, body) = build_multipart_form(
            &[("key", encrypted_key)],
            "data",
            encrypted_file_name,
            encrypted_data,
        );
        let client = self
            .reqwest_client_with_redirect(reqwest::redirect::Policy::none())
            .await?;
        let res = client
            .post(self.api_url(&format!("/ciphers/{entry_path}/attachment")))
            .bearer_auth(access_token)
            .header(
                reqwest::header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body)
            .send()
            .await
            .map_err(|source| Error::Reqwest {
                source: source.without_url(),
            })?;
        if res.status().is_success() {
            let bytes =
                res.bytes().await.map_err(|source| Error::Reqwest {
                    source: source.without_url(),
                })?;
            if let Ok(cipher) =
                serde_json::from_slice::<SyncResCipher>(&bytes)
                && let Some(attachments) = cipher.attachments
                && let Some(att) = attachments
                    .iter()
                    .rev()
                    .find(|a| a.file_name == encrypted_file_name)
                    .or_else(|| attachments.last())
            {
                return Ok(att.id.clone());
            }
            Ok(String::new())
        } else if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(Error::RequestUnauthorized)
        } else {
            Err(Error::RequestFailed {
                status: res.status().as_u16(),
            })
        }
    }

    /// Delete an attachment (`DELETE /ciphers/{id}/attachment/{attachment_id}`).
    pub async fn delete_attachment(
        &self,
        access_token: &str,
        entry_id: &str,
        attachment_id: &str,
    ) -> Result<()> {
        validate_path_id(entry_id)?;
        validate_path_id(attachment_id)?;
        let entry_path = encode_path_segment(entry_id);
        let attachment_path = encode_path_segment(attachment_id);
        let client = self.reqwest_client().await?;
        let res = client
            .delete(self.api_url(&format!(
                "/ciphers/{entry_path}/attachment/{attachment_path}"
            )))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        if res.status().is_success() {
            Ok(())
        } else if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(Error::RequestUnauthorized)
        } else {
            Err(Error::RequestFailed {
                status: res.status().as_u16(),
            })
        }
    }

    fn resolve_direct_upload_url(
        &self,
        entry_id: &str,
        attachment_id: &str,
        upload_url: &str,
    ) -> Result<reqwest::Url> {
        let base = reqwest::Url::parse(&self.base_url).map_err(|_| {
            Error::InvalidAttachment {
                reason: "invalid server URL".to_string(),
            }
        })?;
        let resolved = if upload_url.is_empty() {
            let entry_path = encode_path_segment(entry_id);
            let attachment_path = encode_path_segment(attachment_id);
            self.api_url(&format!(
                "/ciphers/{entry_path}/attachment/{attachment_path}"
            ))
        } else if upload_url.starts_with('/') {
            let base_path = base.path().trim_end_matches('/');
            if !base_path.is_empty()
                && (upload_url == base_path
                    || upload_url.starts_with(&format!("{base_path}/")))
            {
                base.join(upload_url)
                    .map_err(|_| Error::InvalidAttachment {
                        reason: "invalid direct upload URL".to_string(),
                    })?
                    .to_string()
            } else {
                self.api_url(upload_url)
            }
        } else {
            upload_url.to_string()
        };
        let url = reqwest::Url::parse(&resolved).map_err(|_| {
            Error::InvalidAttachment {
                reason: "invalid direct upload URL".to_string(),
            }
        })?;
        validate_blob_url(&url, &base, "unsupported direct upload URL")?;
        if url.origin() != base.origin() {
            return Err(Error::InvalidAttachment {
                reason: "direct upload URL origin does not match API server"
                    .to_string(),
            });
        }
        Ok(url)
    }

    pub fn add(
        &self,
        access_token: &str,
        name: &str,
        data: &crate::db::EntryData,
        notes: Option<&str>,
        folder_id: Option<&str>,
    ) -> Result<()> {
        let req = build_ciphers_post_req(name, data, notes, folder_id);
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(self.api_url("/ciphers"))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn edit(
        &self,
        access_token: &str,
        id: &str,
        org_id: Option<&str>,
        name: &str,
        data: &crate::db::EntryData,
        fields: &[crate::db::Field],
        notes: Option<&str>,
        folder_uuid: Option<&str>,
        history: &[crate::db::HistoryEntry],
    ) -> Result<()> {
        let mut req = CiphersPutReq {
            ty: match data {
                crate::db::EntryData::Login { .. } => 1,
                crate::db::EntryData::SecureNote => 2,
                crate::db::EntryData::Card { .. } => 3,
                crate::db::EntryData::Identity { .. } => 4,
                crate::db::EntryData::SshKey { .. } => unreachable!(),
            },
            folder_id: folder_uuid.map(std::string::ToString::to_string),
            organization_id: org_id.map(std::string::ToString::to_string),
            name: name.to_string(),
            notes: notes.map(std::string::ToString::to_string),
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            fields: fields
                .iter()
                .map(|field| CipherField {
                    ty: field.ty,
                    name: field.name.clone(),
                    value: field.value.clone(),
                    linked_id: field.linked_id,
                })
                .collect(),
            password_history: history
                .iter()
                .map(|entry| CiphersPutReqHistory {
                    last_used_date: entry.last_used_date.clone(),
                    password: entry.password.clone(),
                })
                .collect(),
        };
        match data {
            crate::db::EntryData::Login {
                username,
                password,
                totp,
                uris,
                password_revision_date,
            } => {
                let uris = if uris.is_empty() {
                    None
                } else {
                    Some(
                        uris.iter()
                            .map(|s| CipherLoginUri {
                                uri: Some(s.uri.clone()),
                                match_type: s.match_type,
                            })
                            .collect(),
                    )
                };
                req.login = Some(CipherLogin {
                    username: username.clone(),
                    password: password.clone(),
                    totp: totp.clone(),
                    uris,
                    password_revision_date: password_revision_date.clone(),
                });
            }
            crate::db::EntryData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
            } => {
                req.card = Some(CipherCard {
                    cardholder_name: cardholder_name.clone(),
                    number: number.clone(),
                    brand: brand.clone(),
                    exp_month: exp_month.clone(),
                    exp_year: exp_year.clone(),
                    code: code.clone(),
                });
            }
            crate::db::EntryData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
            } => {
                req.identity = Some(CipherIdentity {
                    title: title.clone(),
                    first_name: first_name.clone(),
                    middle_name: middle_name.clone(),
                    last_name: last_name.clone(),
                    address1: address1.clone(),
                    address2: address2.clone(),
                    address3: address3.clone(),
                    city: city.clone(),
                    state: state.clone(),
                    postal_code: postal_code.clone(),
                    country: country.clone(),
                    phone: phone.clone(),
                    email: email.clone(),
                    ssn: ssn.clone(),
                    license_number: license_number.clone(),
                    passport_number: passport_number.clone(),
                    username: username.clone(),
                });
            }
            crate::db::EntryData::SecureNote => {
                req.secure_note = Some(CipherSecureNote::default());
            }
            crate::db::EntryData::SshKey { .. } => unreachable!(),
        }
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url(&format!("/ciphers/{id}")))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn remove(&self, access_token: &str, id: &str) -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .delete(self.api_url(&format!("/ciphers/{id}")))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn folders(
        &self,
        access_token: &str,
    ) -> Result<Vec<(String, String)>> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .get(self.api_url("/folders"))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let folders_res: FoldersRes = res.json_with_path()?;
                Ok(folders_res
                    .data
                    .iter()
                    .map(|folder| (folder.id.clone(), folder.name.clone()))
                    .collect())
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn create_folder(
        &self,
        access_token: &str,
        name: &str,
    ) -> Result<String> {
        let req = FoldersPostReq {
            name: name.to_string(),
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(self.api_url("/folders"))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let folders_res: FoldersResData = res.json_with_path()?;
                Ok(folders_res.id)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn exchange_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<String> {
        let connect_req = ConnectRefreshTokenReq {
            grant_type: "refresh_token".to_string(),
            client_id: "cli".to_string(),
            refresh_token: refresh_token.to_string(),
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        let connect_res: ConnectRefreshTokenRes = res.json_with_path()?;
        Ok(connect_res.access_token)
    }

    pub async fn exchange_refresh_token_async(
        &self,
        refresh_token: &str,
    ) -> Result<String> {
        let connect_req = ConnectRefreshTokenReq {
            grant_type: "refresh_token".to_string(),
            client_id: "cli".to_string(),
            refresh_token: refresh_token.to_string(),
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        let connect_res: ConnectRefreshTokenRes =
            res.json_with_path().await?;
        Ok(connect_res.access_token)
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn identity_url(&self, path: &str) -> String {
        format!("{}{}", self.identity_url, path)
    }
}

async fn find_free_port(bottom: u16, top: u16) -> Result<u16> {
    for port in bottom..top {
        if tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(port);
        }
    }

    Err(Error::FailedToFindFreePort {
        range: format!("({bottom}..{top})"),
    })
}

#[derive(Clone)]
struct SSOHandlerState {
    state: String,
    sender: tokio::sync::mpsc::Sender<Result<String>>,
}

async fn start_sso_callback_server(
    listener: tokio::net::TcpListener,
    state: &str,
) -> Result<String> {
    let (shut_sender, shut_receiver) = tokio::sync::mpsc::channel(1);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);

    let sso_handler_state = std::sync::Arc::new(SSOHandlerState {
        state: state.to_string(),
        sender: shut_sender,
    });

    let app = axum::Router::new()
        .route("/", axum::routing::get(handle_sso_callback))
        .with_state(sso_handler_state);

    axum::serve(listener, app)
        .with_graceful_shutdown(sso_server_graceful_shutdown(
            sender,
            shut_receiver,
        ))
        .await
        .map_err(|e| Error::FailedToProcessSSOCallback {
            msg: e.to_string(),
        })?;

    receiver.recv().await.unwrap()
}

async fn sso_server_graceful_shutdown(
    sender: tokio::sync::mpsc::Sender<Result<String>>,
    mut receiver: tokio::sync::mpsc::Receiver<Result<String>>,
) {
    sender.send(receiver.recv().await.unwrap()).await.unwrap();
}

async fn handle_sso_callback(
    axum::extract::State(state): axum::extract::State<
        std::sync::Arc<SSOHandlerState>,
    >,
    axum::extract::Query(params): axum::extract::Query<
        std::collections::HashMap<String, String>,
    >,
) -> axum::http::Response<String> {
    match sso_query_code(&params, state.state.as_str()) {
        Ok(sso_code) => {
            state.sender.send(Ok(sso_code)).await.unwrap();

            axum::http::Response::builder().status(axum::http::StatusCode::OK).
            body(
                "<html><head><title>Success | rbw</title></head><body> \
                  <h1>Successfully authenticated with rbw</h1> \
                  <p>You may now close this tab and return to the terminal.</p> \
                  </body></html>".to_string()).unwrap()
        }
        Err(e) => {
            state.sender.send(Err(e)).await.unwrap();

            axum::http::Response::builder().status(axum::http::StatusCode::BAD_REQUEST).
            body(
                "<html><head><title>Failed | rbw</title></head><body> \
                  <h1>Something went wrong logging into the rbw</h1> \
                  <p>You may now close this tab and return to the terminal.</p> \
                  </body></html>".to_string()).unwrap()
        }
    }
}

fn sso_query_code(
    params: &std::collections::HashMap<String, String>,
    state: &str,
) -> Result<String> {
    let sso_code =
        params
            .get("code")
            .ok_or(Error::FailedToProcessSSOCallback {
                msg: "Could not obtain code from the URL".to_string(),
            })?;

    let received_state =
        params
            .get("state")
            .ok_or(Error::FailedToProcessSSOCallback {
                msg: "Could not obtain state from the URL".to_string(),
            })?;

    if received_state.split("_identifier=").next().unwrap() != state {
        return Err(Error::FailedToProcessSSOCallback {
            msg: format!(
                "SSO callback states do not match, sent: {state}, received: {received_state}"
            ),
        });
    }

    Ok(sso_code.clone())
}

fn classify_login_error(error_res: &ConnectErrorRes, code: u16) -> Error {
    let error_desc = error_res.error_description.clone();
    let error_desc = error_desc.as_deref();
    match error_res.error.as_str() {
        "invalid_grant" => match error_desc {
            Some("invalid_username_or_password") => {
                if let Some(error_model) = error_res.error_model.as_ref() {
                    let message = error_model.message.as_str().to_string();
                    return Error::IncorrectPassword { message };
                }
            }
            Some("Two factor required.") => {
                if let Some(providers) =
                    error_res.two_factor_providers.as_ref()
                {
                    return Error::TwoFactorRequired {
                        providers: providers.clone(),
                        providers_data: error_res
                            .two_factor_providers2
                            .clone()
                            .unwrap_or_default(),
                        sso_email_2fa_session_token: error_res
                            .sso_email_2fa_session_token
                            .clone(),
                    };
                }
            }
            Some("Captcha required.") => {
                return Error::RegistrationRequired;
            }
            _ => {}
        },
        "invalid_client" => {
            return Error::IncorrectApiKey;
        }
        "" => {
            // bitwarden_rs returns an empty error and error_description for
            // this case, for some reason
            if (error_desc.is_none() || error_desc == Some(""))
                && let Some(error_model) = error_res.error_model.as_ref()
            {
                let message = error_model.message.as_str().to_string();
                match message.as_str() {
                    "Username or password is incorrect. Try again"
                    | "TOTP code is not a number" => {
                        return Error::IncorrectPassword { message };
                    }
                    s => {
                        if s.starts_with("Invalid TOTP code! Server time: ") {
                            return Error::IncorrectPassword { message };
                        }
                    }
                }
            }
        }
        _ => {}
    }

    log::warn!("unexpected error received during login: {error_res:?}");
    Error::RequestFailed { status: code }
}

const PATH_SEGMENT_ENCODE_SET: &percent_encoding::AsciiSet =
    &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_');

fn encode_path_segment(id: &str) -> percent_encoding::PercentEncode<'_> {
    percent_encoding::utf8_percent_encode(id, PATH_SEGMENT_ENCODE_SET)
}

fn validate_path_id(id: &str) -> Result<()> {
    if id.is_empty() || id == "." || id == ".." {
        return Err(Error::InvalidAttachment {
            reason: "invalid attachment identifiers".to_string(),
        });
    }
    Ok(())
}

fn validate_blob_url(
    url: &reqwest::Url,
    base: &reqwest::Url,
    reason: &str,
) -> Result<()> {
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || (base.scheme() == "https" && url.scheme() != "https")
    {
        return Err(Error::InvalidAttachment {
            reason: reason.to_string(),
        });
    }
    Ok(())
}

fn build_ciphers_post_req(
    name: &str,
    data: &crate::db::EntryData,
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> CiphersPostReq {
    let mut req = CiphersPostReq {
        ty: match data {
            crate::db::EntryData::Login { .. } => 1,
            crate::db::EntryData::SecureNote => 2,
            crate::db::EntryData::Card { .. } => 3,
            crate::db::EntryData::Identity { .. } => 4,
            crate::db::EntryData::SshKey { .. } => 5,
        },
        folder_id: folder_id.map(std::string::ToString::to_string),
        name: name.to_string(),
        notes: notes.map(std::string::ToString::to_string),
        login: None,
        card: None,
        identity: None,
        secure_note: None,
    };
    match data {
        crate::db::EntryData::Login {
            username,
            password,
            totp,
            uris,
            password_revision_date,
        } => {
            let uris = if uris.is_empty() {
                None
            } else {
                Some(
                    uris.iter()
                        .map(|s| CipherLoginUri {
                            uri: Some(s.uri.clone()),
                            match_type: s.match_type,
                        })
                        .collect(),
                )
            };
            req.login = Some(CipherLogin {
                username: username.clone(),
                password: password.clone(),
                totp: totp.clone(),
                uris,
                password_revision_date: password_revision_date.clone(),
            });
        }
        crate::db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => {
            req.card = Some(CipherCard {
                cardholder_name: cardholder_name.clone(),
                number: number.clone(),
                brand: brand.clone(),
                exp_month: exp_month.clone(),
                exp_year: exp_year.clone(),
                code: code.clone(),
            });
        }
        crate::db::EntryData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => {
            req.identity = Some(CipherIdentity {
                title: title.clone(),
                first_name: first_name.clone(),
                middle_name: middle_name.clone(),
                last_name: last_name.clone(),
                address1: address1.clone(),
                address2: address2.clone(),
                address3: address3.clone(),
                city: city.clone(),
                state: state.clone(),
                postal_code: postal_code.clone(),
                country: country.clone(),
                phone: phone.clone(),
                email: email.clone(),
                ssn: ssn.clone(),
                license_number: license_number.clone(),
                passport_number: passport_number.clone(),
                username: username.clone(),
            });
        }
        crate::db::EntryData::SecureNote => {
            req.secure_note = Some(CipherSecureNote::default());
        }
        crate::db::EntryData::SshKey { .. } => unreachable!(),
    }
    req
}

fn build_multipart_form(
    text_fields: &[(&str, &str)],
    file_field: &str,
    file_name: &str,
    file_data: &[u8],
) -> (String, Vec<u8>) {
    let boundary = format!(
        "----rbwBoundary{}",
        rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 24)
    );
    let sanitized_name: String = file_name
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n'))
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            other => vec![other],
        })
        .collect();

    let mut body = Vec::with_capacity(file_data.len() + 256);
    for (name, value) in text_fields {
        body.extend_from_slice(b"--");
        body.extend_from_slice(boundary.as_bytes());
        body.extend_from_slice(
            b"\r\nContent-Disposition: form-data; name=\"",
        );
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(b"\"\r\n\r\n");
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"");
    body.extend_from_slice(file_field.as_bytes());
    body.extend_from_slice(b"\"; filename=\"");
    body.extend_from_slice(sanitized_name.as_bytes());
    body.extend_from_slice(
        b"\"\r\nContent-Type: application/octet-stream\r\n\r\n",
    );
    body.extend_from_slice(file_data);
    body.extend_from_slice(b"\r\n--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"--\r\n");
    (boundary, body)
}

fn format_http_date(time: std::time::SystemTime) -> String {
    const WEEKDAYS: [&str; 7] =
        ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
        "Nov", "Dec",
    ];
    let secs = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    let dow = usize::try_from((days + 4) % 7).unwrap_or(0);
    // Howard Hinnant's civil-from-days algorithm
    let z = i64::try_from(days).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(month <= 2);
    let month_idx = usize::try_from(month - 1).unwrap_or(0);

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[dow], day, MONTHS[month_idx], year, hour, minute, second
    )
}

pub fn parse_webauthn_2fa_options<S: std::hash::BuildHasher>(
    providers_data: &std::collections::HashMap<String, serde_json::Value, S>,
) -> Option<WebAuthnAssertionOptions> {
    let raw = providers_data.get("7")?;
    if raw.is_null() {
        return None;
    }
    let opts: WebAuthnAssertionOptions =
        serde_json::from_value(raw.clone()).ok()?;
    if opts.challenge.is_empty() || opts.allow_credentials.is_empty() {
        return None;
    }
    Some(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_two_factor_providers2_webauthn_bitwarden_and_vaultwarden() {
        let bitwarden_json = r#"{
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["0", "7"],
            "TwoFactorProviders2": {
                "0": null,
                "7": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U",
                    "timeout": 60000,
                    "rpId": "vault.bitwarden.com",
                    "allowCredentials": [
                        {"type": "public-key", "id": "Y3JlZC0x"}
                    ],
                    "userVerification": "discouraged",
                    "extensions": {
                        "appid": "https://vault.bitwarden.com/app-id.json"
                    }
                }
            }
        }"#;
        let err_res: ConnectErrorRes =
            serde_json::from_str(bitwarden_json).unwrap();
        match classify_login_error(&err_res, 400) {
            Error::TwoFactorRequired {
                providers,
                providers_data,
                ..
            } => {
                assert!(providers.contains(&TwoFactorProviderType::WebAuthn));
                let opts =
                    parse_webauthn_2fa_options(&providers_data).unwrap();
                assert_eq!(opts.challenge, "dGVzdC1jaGFsbGVuZ2U");
                assert_eq!(
                    opts.rp_id.as_deref(),
                    Some("vault.bitwarden.com")
                );
                assert_eq!(opts.allow_credentials.len(), 1);
                assert_eq!(opts.allow_credentials[0].id, "Y3JlZC0x");
                assert_eq!(
                    opts.extensions.unwrap().appid.as_deref(),
                    Some("https://vault.bitwarden.com/app-id.json")
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }

        // Vaultwarden #7094 edge case: provider 7 advertised with null data
        let vw_null_json = r#"{
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["0", "7"],
            "TwoFactorProviders2": {"0": null, "7": null}
        }"#;
        let err_res: ConnectErrorRes =
            serde_json::from_str(vw_null_json).unwrap();
        if let Error::TwoFactorRequired { providers_data, .. } =
            classify_login_error(&err_res, 400)
        {
            assert!(parse_webauthn_2fa_options(&providers_data).is_none());
        } else {
            panic!("expected TwoFactorRequired");
        }
    }

    #[test]
    fn test_parse_connect_token_res_with_webauthn_prf_option() {
        let json = r#"{
            "access_token": "tok_a",
            "refresh_token": "tok_r",
            "Key": "2.iv|ct|mac",
            "Kdf": 0,
            "KdfIterations": 600000,
            "UserDecryptionOptions": {
                "HasMasterPassword": true,
                "WebAuthnPrfOption": {
                    "EncryptedPrivateKey": "2.p_iv|p_ct|p_mac",
                    "EncryptedUserKey": "4.u_ct",
                    "CredentialId": "Y3JlZC0x"
                }
            }
        }"#;
        let res: ConnectTokenRes = serde_json::from_str(json).unwrap();
        assert_eq!(res.access_token, "tok_a");
        assert_eq!(res.key.as_deref(), Some("2.iv|ct|mac"));
        assert_eq!(res.kdf, Some(KdfType::Pbkdf2));
        assert_eq!(res.kdf_iterations, Some(600_000));
        let prf = res
            .user_decryption_options
            .unwrap()
            .webauthn_prf_option
            .unwrap();
        assert_eq!(prf.encrypted_private_key, "2.p_iv|p_ct|p_mac");
        assert_eq!(prf.encrypted_user_key, "4.u_ct");
        assert_eq!(prf.credential_id.as_deref(), Some("Y3JlZC0x"));
    }

    #[test]
    fn test_secure_note_post_req_serialization() {
        let req = build_ciphers_post_req(
            "2.name|ct|mac",
            &crate::db::EntryData::SecureNote,
            Some("2.note|ct|mac"),
            Some("folder-1"),
        );
        let val = serde_json::to_value(&req).unwrap();
        assert_eq!(val["type"], 2);
        assert_eq!(val["name"], "2.name|ct|mac");
        assert_eq!(val["notes"], "2.note|ct|mac");
        assert_eq!(val["folderId"], "folder-1");
        assert_eq!(val["secureNote"]["type"], 0);
        assert!(val["login"].is_null());

        let legacy_note: CipherSecureNote =
            serde_json::from_str("{}").unwrap();
        assert_eq!(legacy_note.ty, 0);
    }

    #[test]
    fn test_format_http_date() {
        assert_eq!(
            format_http_date(std::time::UNIX_EPOCH),
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );
        assert_eq!(
            format_http_date(
                std::time::UNIX_EPOCH
                    + std::time::Duration::from_secs(1_700_000_000)
            ),
            "Tue, 14 Nov 2023 22:13:20 GMT"
        );
        assert_eq!(
            format_http_date(
                std::time::UNIX_EPOCH
                    + std::time::Duration::from_hours(474_768)
            ),
            "Thu, 29 Feb 2024 00:00:00 GMT"
        );
    }

    #[test]
    fn test_build_multipart_form_contains_fields_and_binary() {
        let (boundary, body) = build_multipart_form(
            &[("key", "2.kiv|kct|kmac")],
            "data",
            "2.niv|nct|nmac",
            &[2, 0, 255, 10, 13],
        );
        let header = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n2.kiv|kct|kmac\r\n\
             --{boundary}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"2.niv|nct|nmac\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        );
        assert!(body.starts_with(header.as_bytes()));
        let mut expected = header.into_bytes();
        expected.extend_from_slice(&[2, 0, 255, 10, 13]);
        expected
            .extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        assert_eq!(body, expected);
    }
}

#[cfg(test)]
mod attachment_tests {
    use super::*;

    type RequestLog = std::sync::Arc<
        std::sync::Mutex<Vec<(String, String, Option<String>)>>,
    >;

    async fn server(
        mode: &'static str,
    ) -> (String, RequestLog, tokio::task::JoinHandle<()>) {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = requests.clone();
        let url = base.clone();
        let app = axum::Router::new().fallback(
            move |method: axum::http::Method,
                  uri: axum::http::Uri,
                  headers: axum::http::HeaderMap,
                  body: axum::body::Bytes| {
                let seen = seen.clone();
                let url = url.clone();
                async move {
                    seen.lock().unwrap().push((
                        method.to_string(),
                        uri.to_string(),
                        headers
                            .get("Authorization")
                            .map(|v| v.to_str().unwrap().to_string()),
                    ));
                    let mut status = 200;
                    let path = uri
                        .path()
                        .strip_prefix("/api")
                        .unwrap_or_else(|| uri.path());
                    let resp_body = match (method.as_str(), path) {
                        ("GET", "/ciphers/entry") => {
                            if mode == "unauthorized" {
                                status = 401;
                            }
                            let id = if mode == "wrong-entry" {
                                "other"
                            } else {
                                "entry"
                            };
                            let attachment = serde_json::json!({
                                "id": "file",
                                "fileName": "encrypted",
                                "url": format!("{url}/old"),
                                "key": null,
                                "size": "2"
                            });
                            let attachments = if mode == "duplicate" {
                                vec![attachment.clone(), attachment]
                            } else {
                                vec![attachment]
                            };
                            serde_json::to_vec(&serde_json::json!({
                                "id": id,
                                "name": "encrypted",
                                "secureNote": {"type": 0},
                                "reprompt": 1,
                                "deletedDate": if mode == "deleted" { Some("2025-01-01") } else { None },
                                "attachments": attachments
                            }))
                            .unwrap()
                        }
                        ("GET", "/ciphers/entry/attachment/file") => {
                            if mode == "legacy" {
                                status = 404;
                            }
                            if mode == "forbidden" {
                                status = 403;
                            }
                            let id = if mode == "wrong-attachment" {
                                "other"
                            } else {
                                "file"
                            };
                            serde_json::to_vec(&serde_json::json!({
                                "id": id,
                                "fileName": "encrypted",
                                "url": format!("{url}/blob")
                            }))
                            .unwrap()
                        }
                        ("GET", "/blob" | "/old") => vec![0, 255],
                        ("POST", "/ciphers/entry/attachment/v2") => {
                            if mode == "upload-legacy" {
                                status = 404;
                                vec![]
                            } else if mode == "upload-azure" {
                                serde_json::to_vec(&serde_json::json!({
                                    "attachmentId": "att-az-1",
                                    "url": format!("{url}/azure-blob?sv=2019-12-12&sig=abc"),
                                    "fileUploadType": 1
                                }))
                                .unwrap()
                            } else {
                                serde_json::to_vec(&serde_json::json!({
                                    "attachmentId": "att-dir-1",
                                    "url": "/ciphers/entry/attachment/att-dir-1",
                                    "fileUploadType": 0
                                }))
                                .unwrap()
                            }
                        }
                        ("POST", "/ciphers/entry/attachment/att-dir-1") => {
                            let ct = headers
                                .get(axum::http::header::CONTENT_TYPE)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("");
                            assert!(ct.starts_with("multipart/form-data; boundary="));
                            assert!(
                                body.windows(b"name=\"data\"".len())
                                    .any(|w| w == b"name=\"data\"")
                            );
                            if mode == "upload-direct-fail" {
                                status = 500;
                            }
                            vec![]
                        }
                        ("PUT", "/azure-blob") => {
                            assert!(!headers.contains_key("Authorization"));
                            assert_eq!(
                                headers
                                    .get("x-ms-blob-type")
                                    .and_then(|v| v.to_str().ok()),
                                Some("BlockBlob")
                            );
                            assert_eq!(
                                headers
                                    .get("x-ms-version")
                                    .and_then(|v| v.to_str().ok()),
                                Some("2019-12-12")
                            );
                            assert!(headers.contains_key("x-ms-date"));
                            status = 201;
                            vec![]
                        }
                        ("POST", "/ciphers/entry/attachment") => {
                            assert!(
                                body.windows(b"name=\"key\"".len())
                                    .any(|w| w == b"name=\"key\"")
                            );
                            serde_json::to_vec(&serde_json::json!({
                                "id": "entry",
                                "name": "encrypted",
                                "secureNote": {"type": 0},
                                "reprompt": 0,
                                "attachments": [{
                                    "id": "att-legacy-1",
                                    "fileName": "2.fname",
                                    "url": "",
                                    "key": "2.key",
                                    "size": "4"
                                }]
                            }))
                            .unwrap()
                        }
                        (
                            "DELETE",
                            "/ciphers/entry/attachment/att-dir-1"
                            | "/ciphers/entry/attachment/file",
                        ) => {
                            vec![]
                        }
                        _ => {
                            status = 404;
                            vec![]
                        }
                    };
                    axum::http::Response::builder()
                        .status(status)
                        .body(axum::body::Body::from(resp_body))
                        .unwrap()
                }
            },
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (base, requests, task)
    }

    #[tokio::test]
    async fn fresh_metadata_binds_entry_and_never_sends_bearer_to_blob() {
        let (url, requests, task) = server("ok").await;
        let client = Client::new(&url, &url, &url, None);
        let (entry, attachment) = client
            .attachment("synthetic-token", "entry", "file")
            .await
            .unwrap();
        assert!(entry.master_password_reprompt());
        assert_eq!(
            client.attachment_bytes(&attachment).await.unwrap(),
            [0, 255]
        );
        let seen = requests.lock().unwrap();
        assert_eq!(
            seen[0],
            (
                "GET".to_string(),
                "/ciphers/entry".to_string(),
                Some("Bearer synthetic-token".to_string())
            )
        );
        assert_eq!(
            seen[1],
            (
                "GET".to_string(),
                "/ciphers/entry/attachment/file".to_string(),
                Some("Bearer synthetic-token".to_string())
            )
        );
        assert_eq!(seen[2], ("GET".to_string(), "/blob".to_string(), None));
        task.abort();
    }

    #[tokio::test]
    async fn only_404_uses_url_from_fresh_cipher_metadata() {
        let (url, _, task) = server("legacy").await;
        let client = Client::new(&url, &url, &url, None);
        let (_, attachment) =
            client.attachment("token", "entry", "file").await.unwrap();
        assert_eq!(attachment.url, format!("{url}/old"));
        assert_eq!(
            client.attachment_bytes(&attachment).await.unwrap(),
            [0, 255]
        );
        task.abort();
        let (url, requests, task) = server("forbidden").await;
        let client = Client::new(&url, &url, &url, None);
        assert!(matches!(
            client.attachment("token", "entry", "file").await,
            Err(Error::RequestFailed { status: 403 })
        ));
        assert_eq!(requests.lock().unwrap().len(), 2);
        task.abort();
    }

    #[tokio::test]
    async fn mismatched_deleted_duplicate_and_unauthorized_metadata_fail_closed()
     {
        for mode in [
            "wrong-entry",
            "wrong-attachment",
            "deleted",
            "duplicate",
            "unauthorized",
        ] {
            let (url, requests, task) = server(mode).await;
            let client = Client::new(&url, &url, &url, None);
            let result = client.attachment("token", "entry", "file").await;
            if mode == "unauthorized" {
                assert!(matches!(result, Err(Error::RequestUnauthorized)));
            } else {
                assert!(
                    matches!(result, Err(Error::InvalidAttachment { .. })),
                    "{mode}"
                );
            }
            assert!(
                !requests
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(_, url, _)| url == "/blob" || url == "/old")
            );
            task.abort();
        }
    }

    #[tokio::test]
    async fn identifiers_cannot_change_the_resource_path() {
        let (url, requests, task) = server("ok").await;
        let client = Client::new(&url, &url, &url, None);
        assert!(
            client
                .attachment("token", "other/../entry?ignored", "file")
                .await
                .is_err()
        );
        assert_eq!(
            requests.lock().unwrap()[0].1,
            "/ciphers/other%2F%2E%2E%2Fentry%3Fignored"
        );
        task.abort();
    }

    #[tokio::test]
    async fn dot_identifiers_and_unsafe_urls_are_rejected_without_network() {
        let client = Client::new("https://api.example.invalid", "", "", None);
        for id in ["", ".", ".."] {
            assert!(matches!(
                client.attachment("token", id, "file").await,
                Err(Error::InvalidAttachment { .. })
            ));
            assert!(matches!(
                client.attachment("token", "entry", id).await,
                Err(Error::InvalidAttachment { .. })
            ));
            assert!(matches!(
                client.delete_attachment("token", id, "file").await,
                Err(Error::InvalidAttachment { .. })
            ));
        }
        for url in [
            "file:///etc/passwd",
            "http://api.example.invalid/file",
            "https://user:pass@example.invalid/file",
        ] {
            let attachment = crate::attachment::Attachment {
                id: "file".to_string(),
                url: url.to_string(),
                file_name: "encrypted".to_string(),
                key: None,
                size: None,
            };
            assert!(matches!(
                client.attachment_bytes(&attachment).await,
                Err(Error::InvalidAttachment { .. })
            ));
            assert!(matches!(
                client.upload_attachment_azure(url, b"bytes").await,
                Err(Error::InvalidAttachment { .. })
            ));
        }
        // Direct upload must refuse cross-origin URLs so bearer token is never leaked
        assert!(matches!(
            client
                .upload_attachment_direct(
                    "token",
                    "entry",
                    "att",
                    "https://evil.example.invalid/upload",
                    "2.name",
                    b"bytes",
                )
                .await,
            Err(Error::InvalidAttachment { .. })
        ));
        let api_client =
            Client::new("https://vault.example.invalid/api", "", "", None);
        assert_eq!(
            api_client
                .resolve_direct_upload_url(
                    "entry",
                    "att",
                    "/ciphers/entry/attachment/att",
                )
                .unwrap()
                .as_str(),
            "https://vault.example.invalid/api/ciphers/entry/attachment/att"
        );
        assert_eq!(
            api_client
                .resolve_direct_upload_url(
                    "entry",
                    "att",
                    "/api/ciphers/entry/attachment/att",
                )
                .unwrap()
                .as_str(),
            "https://vault.example.invalid/api/ciphers/entry/attachment/att"
        );
    }

    #[tokio::test]
    async fn redirected_blob_requests_stay_unauthenticated() {
        let (url, requests, task) = server("ok").await;
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let target = format!("{url}/blob");
        let app = axum::Router::new().fallback(
            move |headers: axum::http::HeaderMap| {
                let target = target.clone();
                async move {
                    assert!(!headers.contains_key("Authorization"));
                    axum::http::Response::builder()
                        .status(302)
                        .header("Location", target)
                        .body(axum::body::Body::empty())
                        .unwrap()
                }
            },
        );
        let redirect_task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = Client::new(&origin, &origin, &origin, None);
        let attachment = crate::attachment::Attachment {
            id: "file".to_string(),
            url: origin,
            file_name: "encrypted".to_string(),
            key: None,
            size: None,
        };
        assert_eq!(
            client.attachment_bytes(&attachment).await.unwrap(),
            [0, 255]
        );
        assert_eq!(
            requests.lock().unwrap()[0],
            ("GET".to_string(), "/blob".to_string(), None)
        );
        redirect_task.abort();
        task.abort();
    }

    #[tokio::test]
    async fn upload_direct_azure_legacy_cleanup_and_delete() {
        let encrypted = crate::attachment::EncryptedAttachment {
            file_name: "2.fname".to_string(),
            key: "2.key".to_string(),
            data: vec![2, 1, 2, 3],
        };

        // 1. Direct upload (Vaultwarden)
        {
            let (url, requests, task) = server("upload-direct").await;
            let config = crate::config::Config {
                base_url: Some(url.clone()),
                ..crate::config::Config::default()
            };
            let (_, att_id) = crate::actions::upload_attachment(
                &config, "tok", "ref", "entry", &encrypted,
            )
            .await
            .unwrap();
            assert_eq!(att_id, "att-dir-1");
            let seen = requests.lock().unwrap();
            assert_eq!(seen[0].1, "/api/ciphers/entry/attachment/v2");
            assert_eq!(seen[1].1, "/api/ciphers/entry/attachment/att-dir-1");
            assert_eq!(seen[1].2.as_deref(), Some("Bearer tok"));
            task.abort();
        }

        // 2. Azure upload (Bitwarden Cloud)
        {
            let (url, requests, task) = server("upload-azure").await;
            let config = crate::config::Config {
                base_url: Some(url.clone()),
                ..crate::config::Config::default()
            };
            let (_, att_id) = crate::actions::upload_attachment(
                &config, "tok", "ref", "entry", &encrypted,
            )
            .await
            .unwrap();
            assert_eq!(att_id, "att-az-1");
            let seen = requests.lock().unwrap();
            assert_eq!(seen[0].1, "/api/ciphers/entry/attachment/v2");
            assert_eq!(seen[1].0, "PUT");
            assert_eq!(seen[1].2, None);
            task.abort();
        }

        // 3. Direct upload failure triggers cleanup DELETE
        {
            let (url, requests, task) = server("upload-direct-fail").await;
            let config = crate::config::Config {
                base_url: Some(url.clone()),
                ..crate::config::Config::default()
            };
            assert!(
                crate::actions::upload_attachment(
                    &config, "tok", "ref", "entry", &encrypted,
                )
                .await
                .is_err()
            );
            let seen = requests.lock().unwrap();
            assert_eq!(seen[2].0, "DELETE");
            assert_eq!(seen[2].1, "/api/ciphers/entry/attachment/att-dir-1");
            task.abort();
        }

        // 4. Legacy 404 fallback
        {
            let (url, requests, task) = server("upload-legacy").await;
            let config = crate::config::Config {
                base_url: Some(url.clone()),
                ..crate::config::Config::default()
            };
            let (_, att_id) = crate::actions::upload_attachment(
                &config, "tok", "ref", "entry", &encrypted,
            )
            .await
            .unwrap();
            assert_eq!(att_id, "att-legacy-1");
            assert_eq!(
                requests.lock().unwrap()[1].1,
                "/api/ciphers/entry/attachment"
            );
            task.abort();
        }

        // 5. Explicit delete
        {
            let (url, requests, task) = server("ok").await;
            let client = Client::new(&url, &url, &url, None);
            client
                .delete_attachment("tok", "entry", "file")
                .await
                .unwrap();
            assert_eq!(
                requests.lock().unwrap()[0],
                (
                    "DELETE".to_string(),
                    "/ciphers/entry/attachment/file".to_string(),
                    Some("Bearer tok".to_string())
                )
            );
            task.abort();
        }
    }
}
