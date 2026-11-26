---
name: rbw
description: "Bitwarden vault passwords, TOTP, SSH keys, notes, folders via rbw MCP server or CLI"
---

# rbw Bitwarden Vault Skill

Use this skill to read, search, generate, or manage Bitwarden / Vaultwarden vault entries through the `rbw` MCP 2.0 server (`rbw mcp`), or via the `rbw` CLI when the MCP server is read-only or unavailable.

## Hard Rules

1. Never ask the user to type their master password, 2FA code, or API key in chat; call `vault_session` with `action: "unlock"` to trigger local Touch ID, YubiKey, or `pinentry`.
2. Never echo retrieved passwords, TOTP secrets, CVVs, SSNs, or SSH private keys into logs, source files, git commits, or long prose; prefer `copy_to_clipboard: true` on `vault_get` when the user only needs to paste the secret.
3. Never call `vault_get` with `mode: "full"` before inspecting `vault_search` or `vault_get` with `mode: "summary"`.
4. Never call `vault_delete` without explicit user confirmation naming the target item or attachment.
5. Never invent entry UUIDs, folder names, field names, or file paths; read them from `vault_status`, `vault_search`, or `vault_get` (`mode: "summary"`).

## Routing Table

| User goal | First step | Reference to read |
|---|---|---|
| Check lock state, accounts, or folders | Run Step 1 (`vault_status`) | [references/tools.md](references/tools.md) |
| Find an entry by name, URL, folder, or type | Run Step 2 (`vault_search`) | [references/tools.md](references/tools.md) |
| Get a password, username, TOTP, note, SSH key, or history | Run Step 2 then Step 3 (`vault_get`) | [references/workflows.md](references/workflows.md) |
| Generate a new password or passphrase | Call `vault_generate` directly | [references/tools.md](references/tools.md) |
| Unlock, lock, sync, or switch active account | Call `vault_session` | [references/workflows.md](references/workflows.md) |
| Create or update an entry or folder (`--allow-write`) | Read workflow then call `vault_write` | [references/workflows.md](references/workflows.md) |
| Delete an item or attachment (`--allow-write`) | Confirm with user then call `vault_delete` | [references/tools.md](references/tools.md) |
| Download or upload an attachment (`--allowed-dir`) | Read workflow then call `vault_attachment` | [references/workflows.md](references/workflows.md) |
| Vault is logged out or MCP lacks write permission | Use CLI fallback workflow | [references/workflows.md](references/workflows.md) |

## Core Procedure

### 1. Verify vault session and account

Input: optional account name from the user request (omit to use the active account).

1. Call MCP tool `vault_status` with `{}` (or `{"account": "<name>", "include_folders": true}` when folders are needed).
2. Read `agent_running`, `selected_account`, and the matching entry in `accounts` (`status` is `"unlocked"`, `"locked"`, or `"logged out"`).
3. Branch on `status`:

| `status` value | Next action |
|---|---|
| `"unlocked"` | Continue to Step 2. |
| `"locked"` | Call `vault_session` with `{"action": "unlock"}` (add `"account": "<name>"` if targeting a non-active account), wait for the user's local Touch ID / YubiKey / pinentry check, then continue to Step 2. |
| `"logged out"` | Stop MCP calls and tell the user to run `rbw login` in a terminal, then retry. |
| `accounts` is empty | Stop MCP calls and tell the user to run `rbw account add` in a terminal. |

Expected: `vault_status` returns `status: "unlocked"` for the target account.

If `vault_session` unlock times out or fails: retry at most 1 time after informing the user to complete the local prompt. After 2 failed attempts, stop and report the exact error message.

Done when: the target account is `"unlocked"`.

### 2. Locate the target entry (metadata only)

Input: search term, URL, folder, or entry type (`login`, `note`, `card`, `identity`, `ssh_key`) from the user request.

1. Call MCP tool `vault_search` with only the filters the user gave, e.g. `{"query": "github", "entry_type": "login", "limit": 20}`.
2. Inspect `total` and `items`. Each item contains metadata only (`id`, `type`, `name`, `username`, `folder`, `uris`, `has_totp`, `attachment_count`, `reprompt`).
3. Branch on `total`:

| Match count | Next action |
|---|---|
| `1` | Record `items[0].id` and continue to Step 3. |
| `> 1` | Present a compact list of `name`, `username`, `folder`, `type`, and `id` (at most 10 rows) and ask the user which entry to use. |
| `0` | If the vault may be stale, call `vault_session` with `{"action": "sync"}` once and re-run `vault_search`; if still `0`, stop and report no matching entry. |

Expected: one unambiguous entry UUID in `items[0].id`.

If `vault_search` returns a locked-vault error: run Step 1, then retry `vault_search` once. After 2 failed attempts, stop and report the error.

Done when: you hold the exact `id` of the single target entry.

### 3. Inspect summary and fetch only the requested field

Input: `entry_id` from Step 2; requested secret or metadata field from the user.

1. Call MCP tool `vault_get` with `{"query": "<entry_id>", "mode": "summary"}` to inspect `available_fields`, `has_totp`, `history_count`, `reprompt`, and `attachments` without exposing secrets.
2. Decide the minimum retrieval call:

| What the user wants | `vault_get` arguments |
|---|---|
| Paste password or TOTP into another app | `{"query": "<entry_id>", "mode": "field", "field": "password", "copy_to_clipboard": true}` or `{"query": "<entry_id>", "mode": "totp", "copy_to_clipboard": true}` |
| Read one specific field in chat | `{"query": "<entry_id>", "mode": "field", "field": "<field_from_available_fields>"}` |
| Read live TOTP code in chat | `{"query": "<entry_id>", "mode": "totp"}` |
| Read password history | `{"query": "<entry_id>", "mode": "history"}` (add `"version": "1"` or `"current"` for one version) |
| Inspect every field of the entry | `{"query": "<entry_id>", "mode": "full"}` |
| Only metadata or attachment list | Stop after `mode: "summary"` |

3. Repeat the hard rule before returning: never write secret values to files or logs, and report results in ≤ 10 lines.

Worked example (`vault_get` summary -> clipboard password):

```json
// Call 1: vault_get
{"query": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", "mode": "summary"}
// Response 1 (excerpt)
{"id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", "type": "login", "name": "github.com", "username": "alice", "has_totp": true, "available_fields": ["username", "password", "totp", "uris"]}

// Call 2: vault_get
{"query": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", "mode": "field", "field": "password", "copy_to_clipboard": true}
// Response 2
{"entry_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", "entry_name": "github.com", "field": "password", "copied_to_clipboard": true}
```

Expected: `vault_get` succeeds and returns either `copied_to_clipboard: true` or the exact requested field.

If `reprompt: true` causes a pinentry error: tell the user the entry has master-password reprompt enabled and requires a GUI pinentry prompt or `rbw get <id>` in a terminal. If `copy_to_clipboard: true` fails because `clipboard` is unavailable, ask the user before falling back to `copy_to_clipboard: false`.

Done when: the requested value is copied to clipboard or reported concisely to the user.

### 4. Write, delete, or transfer attachments (when enabled)

Input: user request to create, update, delete, or transfer an attachment.

1. Read [references/workflows.md](references/workflows.md) for the exact step-by-step procedure and [references/tools.md](references/tools.md) for parameter schemas.
2. Check if `vault_write`, `vault_delete`, or `vault_attachment` is listed in your available MCP tools.
3. If the required write or attachment tool is missing, tell the user which flag enables it (`rbw mcp --allow-write` or `rbw mcp --allowed-dir <DIR>`) or offer the exact `rbw` CLI command from [references/workflows.md](references/workflows.md).

Expected: the operation completes cleanly or the user receives the exact flag/CLI fallback.

If a write or transfer tool returns a validation or path-allowlist error: fix the parameter once from [references/tools.md](references/tools.md) and retry. After 2 failed attempts, stop and report the error.

Done when: the write/delete/attachment response confirms completion, or the exact CLI fallback is provided.
