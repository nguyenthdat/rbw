# rbw Vault Workflows

Contents: 1. Retrieve a Secret or TOTP Safely · 2. Unlock Vault or Switch Accounts · 3. Create or Rotate a Login Password · 4. Transfer an Attachment · 5. CLI Fallback Commands

## 1. Retrieve a Secret or TOTP Safely

Input: service name or URL from the user; whether the user needs to paste it locally or read it in chat.

1. Call `vault_search` with `{"query": "<service>"}` (or `{"url": "<url>"}` when given a URL).
2. If `total == 0`, call `vault_session` with `{"action": "sync"}` once and repeat step 1.
3. Call `vault_get` with `{"query": "<id>", "mode": "summary"}` to verify `available_fields` and `has_totp`.
4. Call `vault_get` with the narrowest mode:
   - Paste locally: `{"query": "<id>", "mode": "field", "field": "password", "copy_to_clipboard": true}` (or `mode: "totp"`).
   - Read in chat: `{"query": "<id>", "mode": "field", "field": "<field>"}` (or `mode: "totp"`).

Expected: response contains `copied_to_clipboard: true` or only the single requested field.

If `vault_search` fails with `is locked`: run Workflow 2, then restart at step 1. After 2 failed attempts, stop and report the error.

Done when: the user has the value in clipboard or receives the single requested field in ≤ 10 lines.

## 2. Unlock Vault or Switch Accounts

Input: optional target account name, email, or server.

1. Call `vault_status` with `{}` to list all accounts and their `status`.
2. If the user wants a different default account, call `vault_session` with `{"action": "switch_account", "target": "<account>"}`.
3. If the target account has `status: "logged out"`, stop and ask the user to run `rbw login` in a terminal.
4. If the target account has `status: "locked"`, call `vault_session` with `{"action": "unlock"}` (include `"account": "<name>"` if not switching the active account).

Expected: `vault_session` returns `status: "unlocked"`.

If unlock times out or pinentry fails: inform the user to respond to the local Touch ID, YubiKey, or pinentry prompt and retry at most 1 time. If it still fails, ask the user to run `rbw unlock` in a terminal.

Done when: `vault_status` reports `status: "unlocked"` for the target account.

## 3. Create or Rotate a Login Password

Input: entry name (or existing entry UUID), optional username, folder, URIs, and password generation rules.

1. Verify `vault_write` is available in your tool list. If not, switch to Workflow 5.
2. For a **new login** with a generated password, call `vault_write`:
   ```json
   {
     "action": "create_item",
     "entry_type": "login",
     "name": "Example Service",
     "folder": "Work",
     "login": {"username": "alice@example.com", "uris": ["https://example.com"]},
     "generate_password": {"length": 24, "style": "all_chars"}
   }
   ```
3. For **rotating an existing login's password** (preserves the previous password in `password_history`):
   - Find the exact UUID with `vault_search`.
   - Call `vault_write`:
     ```json
     {
       "action": "update_item",
       "query": "<entry_uuid>",
       "generate_password": {"length": 24, "style": "all_chars"}
     }
     ```
4. If the user needs the newly generated password on the clipboard, call `vault_get` with `{"query": "<entry_uuid>", "mode": "field", "field": "password", "copy_to_clipboard": true}`.

Expected: `vault_write` returns `"password_generated": true` and the saved `id`.

If `vault_write` fails with a lock or network error: unlock once (Workflow 2) or retry once. After 2 failed attempts, stop and report the error.

Done when: `vault_write` returns the created or updated entry `id` without leaking plaintext secrets into logs.

## 4. Transfer an Attachment

Input: entry UUID or name, attachment ID/filename (for download) or source file path (for upload), and target path inside `--allowed-dir`.

1. Verify `vault_attachment` is available in your tool list. If missing, tell the user to start the server with `rbw mcp --allowed-dir <DIR>` (and `--allow-write` for uploads) or use Workflow 5.
2. Call `vault_get` with `{"query": "<entry_id>", "mode": "summary"}` to inspect existing `attachments` (`id`, `file_name`, `size`).
3. Call `vault_attachment`:
   - Download (target file must not already exist; written with mode `0600`):
     ```json
     {"action": "download", "query": "<entry_id>", "attachment": "<attachment_id>", "path": "/allowed/dir/file.bin"}
     ```
   - Upload (requires `--allow-write` and `--allowed-dir`):
     ```json
     {"action": "upload", "query": "<entry_id>", "path": "/allowed/dir/cert.pem", "file_name": "cert.pem"}
     ```

Expected: `vault_attachment` returns `entry_id`, `attachment_id`, `path`, and `bytes`.

If `path` is rejected as outside allowed directories or already exists: ask the user for a new path inside `--allowed-dir` and retry once. After 2 failed attempts, stop and report the error.

Done when: `vault_attachment` returns the written or uploaded byte count.

## 5. CLI Fallback Commands

Use these exact commands when `rbw mcp` is not running, is read-only, or the account is logged out:

| Task | Exact CLI command |
|---|---|
| Add account / log in | `rbw account add` or `rbw login` |
| Check account status | `rbw account list --raw` |
| Unlock / lock / sync | `rbw unlock`, `rbw lock`, `rbw lock --all`, `rbw sync` |
| Search entries (JSON) | `rbw search "<term>" --raw` |
| Copy password or TOTP to clipboard | `rbw get "<name>" --clipboard`, `rbw code "<name>" --clipboard` |
| Get single field | `rbw get "<name>" --field <field>` |
| View password history | `rbw history "<name>" --raw` |
| Create login / secure note | `rbw add "<name>" "<user>"`, `printf '%s\n' "<note>" \| rbw add --note "<name>"` |
| Generate and save password | `rbw generate 24 "<name>" "<user>"` |
| Upload / download attachment | `rbw attachment upload "<name>" --file <path>`, `rbw attachment download "<name>" -A <id> -o <path>` |
| Install this skill locally | `rbw mcp install-skill --target agy` (or `omp`, `claude`, `agents`, `all`) |
