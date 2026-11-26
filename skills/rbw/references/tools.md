# rbw MCP Tools Reference

Contents: 1. Availability Matrix · 2. Read & Session Tools · 3. Write, Delete & Attachment Tools · 4. Error Recovery Table

## 1. Availability Matrix

| Tool | Enabled when | Annotations (`readOnly` / `destructive` / `idempotent` / `openWorld`) |
|---|---|---|
| `vault_status` | Always | `true / false / true / false` |
| `vault_search` | Always | `true / false / true / false` |
| `vault_get` | Always | `true / false / true / false` |
| `vault_generate` | Always | `true / false / false / false` |
| `vault_session` | Always | `false / false / true / true` |
| `vault_write` | `rbw mcp --allow-write` (`RBW_MCP_ALLOW_WRITE=1`) | `false / false / false / true` |
| `vault_delete` | `rbw mcp --allow-write` (`RBW_MCP_ALLOW_WRITE=1`) | `false / true / false / true` |
| `vault_attachment` | `rbw mcp --allowed-dir <DIR>` (`RBW_MCP_ALLOWED_DIRS`) — `upload` also requires `--allow-write` | `false / false / false / true` |

Every tool accepts an optional `account` string (account alias, email, or server) that overrides the active account for that single call.

## 2. Read & Session Tools

### `vault_status`

Parameters:
- `account` (string, optional): account selector to inspect.
- `include_folders` (boolean, optional, default `false`): fetch and decrypt folder list (requires target account to be unlocked).

Example:
```json
{"include_folders": true}
```
Output shape:
```json
{
  "agent_running": true,
  "active_account": "personal",
  "selected_account": "personal",
  "accounts": [{"name": "personal", "email": "alice@example.com", "server": "bitwarden.com", "active": true, "status": "unlocked"}],
  "folders": [{"id": "f-1", "name": "Work"}]
}
```

### `vault_search`

Lists or searches vault entries. Returns metadata only — never passwords, notes, TOTP seeds, CVVs, SSNs, or SSH private keys.

Parameters:
- `query` (string, optional): case-insensitive substring across name, username, URIs, notes, and non-hidden custom fields.
- `url` (string, optional): URL or hostname matched using each URI's Bitwarden match rule.
- `folder` (string, optional): case-insensitive folder name filter.
- `entry_type` (enum, optional): `"login"` | `"note"` | `"card"` | `"identity"` | `"ssh_key"`.
- `limit` (integer, optional, default `50`, range `1..=200`): page size.
- `offset` (integer, optional, default `0`): pagination offset.
- `account` (string, optional).

Example:
```json
{"query": "aws", "entry_type": "login", "folder": "Work", "limit": 20}
```
Output shape:
```json
{
  "total": 1,
  "returned": 1,
  "offset": 0,
  "limit": 20,
  "items": [
    {"id": "uuid-1", "type": "login", "name": "AWS Prod", "username": "ops", "folder": "Work", "uris": ["https://console.aws.amazon.com"], "has_totp": true, "attachment_count": 0, "reprompt": false}
  ]
}
```

### `vault_get`

Retrieves one entry by UUID, exact/partial name, or URL.

Parameters:
- `query` (string, required): entry UUID (preferred), name, or URL.
- `mode` (enum, optional, default `"summary"`):
  - `"summary"`: metadata, `available_fields`, `has_totp`, `history_count`, `reprompt`, `attachments` (no secret values).
  - `"field"`: single field named by `field` (`"password"`, `"username"`, `"totp"`, `"totp_secret"`, `"notes"`, `"uris"`, `"public_key"`, `"private_key"`, `"fingerprint"`, card/identity fields, or custom field name).
  - `"totp"`: live TOTP `code`, `period`, `remaining_seconds`.
  - `"history"`: chronological password versions (`v1` oldest to `current`). Optional `version` (`"1"`, `"v1"`, `"current"`).
  - `"full"`: full decrypted entry JSON.
- `field` (string, required when `mode = "field"`).
- `version` (string, optional with `mode = "history"`).
- `username` (string, optional): disambiguate duplicate entry names.
- `folder` (string, optional): disambiguate duplicate entry names.
- `ignore_case` (boolean, optional, default `false`).
- `copy_to_clipboard` (boolean, optional, default `false`): valid with `mode = "field"`, `"totp"`, or `"history"` + `version`. Copies value directly via `rbw-agent` and omits the plaintext from the JSON response.
- `account` (string, optional).

### `vault_generate`

Generates a random password or EFF diceware passphrase without modifying the vault.

Parameters:
- `length` (integer, optional): character count (default `20`, range `1..=256`) or word count for `diceware` (default `5`, range `1..=32`).
- `style` (enum, optional, default `"all_chars"`): `"all_chars"` | `"no_symbols"` | `"numbers"` | `"nonconfusables"` | `"diceware"`.

Example:
```json
{"length": 24, "style": "no_symbols"}
```
Output shape:
```json
{"password": "<generated>", "length": 24, "style": "no_symbols"}
```

### `vault_session`

Controls unlock, lock, sync, and active account switching. Never accepts passwords.

Parameters:
- `action` (enum, required): `"unlock"` | `"lock"` | `"sync"` | `"switch_account"`.
- `account` (string, optional): target account for `unlock`, `lock`, or `sync`.
- `all` (boolean, optional, default `false`): with `action = "lock"`, lock every configured account.
- `target` (string, optional): account name, email, server, or `email@server` for `switch_account`.
- `email` (string, optional): email filter for `switch_account`.
- `server` (string, optional): server filter for `switch_account`.

## 3. Write, Delete & Attachment Tools

### `vault_write` (requires `--allow-write`)

Parameters:
- `action` (enum, required): `"create_item"` | `"update_item"` | `"create_folder"`.
- `account` (string, optional).
- For `create_folder`: `name` (string, required).
- For `create_item`:
  - `entry_type` (enum, optional, default `"login"`): `"login"` | `"note"` | `"card"` | `"identity"` (`ssh_key` creation is unsupported).
  - `name` (string, required), `folder` (string, optional — created if missing), `notes` (string, optional).
  - `fields` (array, optional): `[{"name": "...", "value": "...", "type": "text"|"hidden"|"boolean"}]`.
  - `login` (object, optional): `{username?, password?, totp?, uris?: string[]}`.
  - `card` (object, optional): `{cardholder_name?, number?, brand?, exp_month?, exp_year?, code?}`.
  - `identity` (object, optional): `{title?, first_name?, middle_name?, last_name?, address1?, address2?, address3?, city?, state?, postal_code?, country?, phone?, email?, ssn?, license_number?, passport_number?, username?}`.
  - `generate_password` (object, optional, login only): `{length?, style?}` — generates and stores password server-side without echoing it in the response.
- For `update_item`:
  - `query` (string, required): target entry UUID (preferred), name, or URL.
  - `match_username` (string, optional), `match_folder` (string, optional), `ignore_case` (boolean, optional).
  - Partial patch fields (omitted fields stay unchanged): `name`, `folder`, `clear_folder` (boolean), `notes` (pass `""` to clear), `fields` (replaces custom fields if supplied), `login`, `card`, `identity`, `generate_password`.
  - Changing a login password automatically appends the previous password to `password_history`.

### `vault_delete` (requires `--allow-write`, `destructiveHint: true`)

Parameters:
- `target` (enum, required): `"item"` | `"attachment"`.
- `query` (string, required): entry UUID (preferred), name, or URL.
- `attachment` (string, required when `target = "attachment"`): attachment ID (preferred) or exact filename.
- `username` (string, optional), `folder` (string, optional), `ignore_case` (boolean, optional), `account` (string, optional).

### `vault_attachment` (requires `--allowed-dir`; `upload` also requires `--allow-write`)

Parameters:
- `action` (enum, required): `"download"` | `"upload"`.
- `query` (string, required): entry UUID (preferred), name, or URL.
- `path` (string, required): destination file path (must not already exist; written atomically with `0600`) or source file path, strictly inside a configured `--allowed-dir`.
- `attachment` (string, required for `download`): attachment ID or exact filename.
- `file_name` (string, optional for `upload`): override stored filename in Bitwarden.
- `username` (string, optional), `folder` (string, optional), `ignore_case` (boolean, optional), `account` (string, optional).

## 4. Error Recovery Table

| Error message pattern | Cause | Recovery action |
|---|---|---|
| `vault for account '...' is locked` | Agent has no unlocked keys in RAM | Call `vault_session` with `{"action": "unlock"}` once. |
| `account '...' is logged out` | No local login tokens in `db.json` | Stop MCP calls and instruct the user to run `rbw login` in a terminal. |
| `multiple entries found` | Ambiguous entry name | Call `vault_search` and retry `vault_get` with the exact UUID. |
| `no entry found` | Stale cache or typo | Call `vault_session` with `{"action": "sync"}`, then search again with `vault_search`. |
| `path ... is outside allowed directories` | File path not under `--allowed-dir` | Ask the user for a path inside the configured `--allowed-dir` or restart `rbw mcp` with `--allowed-dir <DIR>`. |
| `upload requires --allow-write` | Server is in read-only mode | Instruct the user to restart with `rbw mcp --allow-write --allowed-dir <DIR>` or run `rbw attachment upload`. |
| `clipboard support is not enabled` | Binary compiled without `clipboard` feature | Ask the user before retrying `vault_get` with `copy_to_clipboard: false`. |
