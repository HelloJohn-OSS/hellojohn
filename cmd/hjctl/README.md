# hjctl — HelloJohn CLI

`hjctl` is the official command-line interface for [HelloJohn](https://github.com/dropDatabas3/hellojohn), a self-hosted multi-tenant authentication and identity platform. It lets you manage every aspect of the platform directly from a terminal: tenants, users, OAuth clients, API keys, RBAC roles, webhooks, sessions, and more.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [Global Flags](#global-flags)
  - [Environment Variables](#environment-variables)
  - [Config File](#config-file)
- [Output Formats](#output-formats)
- [Command Reference](#command-reference)
  - [auth](#auth)
  - [config](#config)
  - [api-key](#api-key)
  - [tenant](#tenant)
  - [user](#user)
  - [client](#client)
  - [scope](#scope)
  - [role](#role)
  - [key](#key)
  - [audit](#audit)
  - [system](#system)
  - [webhook](#webhook)
  - [session](#session)
  - [mfa](#mfa)
  - [token](#token)
  - [consent](#consent)
  - [claim](#claim)
  - [invitation](#invitation)
  - [mcp](#mcp)
  - [local](#local)
- [Examples](#examples)

---

## Installation

Build from source (requires Go 1.21+):

```bash
go build -o hjctl ./cmd/hjctl
```

Or using the Makefile (from the repo root):

```bash
make hjctl
```

Move the binary to your PATH:

```bash
mv hjctl /usr/local/bin/hjctl
```

---

## Quick Start

```bash
# 1. Authenticate
hjctl auth login --base-url http://localhost:8080 --api-key hj_admin_...

# 2. List tenants
hjctl tenant list

# 3. Create a tenant
hjctl tenant create --slug acme --name "ACME Corp" --language en

# 4. List users in a tenant
hjctl user list --tenant acme

# 5. Create a user
hjctl user create --tenant acme --email alice@acme.com --password s3cr3t --name "Alice"
```

---

## Configuration

### Global Flags

These flags are available on every command:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--base-url` | | | HelloJohn server URL (e.g. `http://localhost:8080`) |
| `--api-key` | | | API key for authentication (`hj_admin_...`) |
| `--output` | `-o` | `json` | Output format: `json`, `table`, `yaml` |
| `--tenant` | `-t` | | Default tenant slug (for tenant-scoped commands) |
| `--timeout` | | `30` | HTTP timeout in seconds |

### Environment Variables

Environment variables override the config file but are overridden by flags:

| Variable | Flag equivalent |
|----------|----------------|
| `HELLOJOHN_BASE_URL` | `--base-url` |
| `HELLOJOHN_API_KEY` | `--api-key` |
| `HELLOJOHN_DEFAULT_TENANT` | `--tenant` |
| `HELLOJOHN_OUTPUT` | `--output` |

### Config File

Stored at `~/.hjctl/config.yaml`. Managed via `hjctl auth login` and `hjctl config set`:

```yaml
base_url: http://localhost:8080
api_key: hj_admin_...
default_tenant: acme
output: table
```

Valid config keys: `base_url`, `api_key`, `default_tenant`, `output`.

---

## Output Formats

| Format | Flag | Notes |
|--------|------|-------|
| JSON | `-o json` | Default. Pretty-printed, suitable for scripting with `jq`. |
| Table | `-o table` | Human-readable ASCII table. Best for interactive use. |
| YAML | `-o yaml` | YAML representation of the JSON response. |

---

## Command Reference

---

### auth

Authenticate and manage stored credentials.

```
hjctl auth <subcommand>
```

| Subcommand | Description |
|------------|-------------|
| `login` | Validate an API key and save credentials to `~/.hjctl/config.yaml`. |
| `logout` | Remove the stored API key from the config file. |
| `whoami` | Show the details of the currently authenticated API key. |

**Examples:**

```bash
hjctl auth login --base-url http://localhost:8080 --api-key hj_admin_abc123
hjctl auth whoami
hjctl auth logout
```

---

### config

Manage CLI configuration values directly.

```
hjctl config <subcommand>
```

| Subcommand | Description |
|------------|-------------|
| `set <key> <value>` | Set a config value (`base_url`, `api_key`, `default_tenant`, `output`). |
| `get <key>` | Print the current value of a config key. |
| `show` | Print all config values. |

**Examples:**

```bash
hjctl config set default_tenant acme
hjctl config set output table
hjctl config get base_url
hjctl config show
```

---

### api-key

Manage HelloJohn API keys (the keys used to authenticate `hjctl` and the MCP server itself).

> **Security note:** The raw token is only shown once at creation or rotation. Store it immediately.

```
hjctl api-key <subcommand>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List all API keys (IDs, names, scopes, prefixes — never hashes or tokens). |
| `create` | Create a new API key. Token shown once. |
| `get <id>` | Get details of a specific API key by UUID. |
| `revoke <id>` | Permanently revoke an API key. |
| `rotate <id>` | Revoke the old key and issue a new one. New token shown once. |

**Flags for `create`:**

| Flag | Required | Description |
|------|----------|-------------|
| `--name` | Yes | Descriptive name for the key. |
| `--scope` | Yes | `admin`, `readonly`, `cloud`, or `tenant:<slug>`. |
| `--expires-in` | No | Expiration duration, e.g. `720h`, `30d`. Omit for no expiration. |

**Examples:**

```bash
hjctl api-key list
hjctl api-key create --name "CI Pipeline" --scope readonly --expires-in 720h
hjctl api-key get 550e8400-e29b-41d4-a716-446655440000
hjctl api-key rotate 550e8400-e29b-41d4-a716-446655440000
hjctl api-key revoke 550e8400-e29b-41d4-a716-446655440000
```

---

### tenant

Manage tenants. Tenants are isolated identity namespaces — each has its own database, settings, users, and clients.

```
hjctl tenant <subcommand>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List all tenants. |
| `get <slug-or-id>` | Get tenant details by slug or UUID. |
| `create` | Create a new tenant. |
| `update <slug-or-id>` | Update a tenant's name or language. |
| `delete <slug-or-id>` | Delete a tenant. **Irreversible.** |
| `disable <slug-or-id>` | Disable a tenant (blocks all logins). |
| `enable <slug-or-id>` | Re-enable a disabled tenant. |
| `export <slug-or-id>` | Export tenant configuration as JSON. |
| `import` | Import a tenant from a JSON export file or stdin. |
| `get-settings <slug-or-id>` | Get the tenant's runtime settings (SMTP, DB, cache, etc.). |
| `set-settings <slug-or-id>` | Update tenant settings from a JSON file or stdin. |
| `check-db <slug-or-id>` | Check database connectivity for a tenant. |
| `rotate-keys <slug-or-id>` | Rotate the JWT signing keys for a tenant. |
| `stats <slug-or-id>` | Get tenant statistics (user count, sessions, etc.). |
| `list-admins <slug-or-id>` | List admin users for a tenant. |
| `add-admin <slug-or-id>` | Grant admin rights to a user in a tenant. |
| `remove-admin <slug-or-id> <sub>` | Revoke admin rights from a user. |

**Flags for `create`:**

| Flag | Required | Description |
|------|----------|-------------|
| `--slug` | Yes | Unique URL-safe identifier (e.g. `acme`). |
| `--name` | Yes | Display name (e.g. `"ACME Corp"`). |
| `--language` | No | Default language code (default: `en`). |

**Examples:**

```bash
hjctl tenant list
hjctl tenant create --slug acme --name "ACME Corp"
hjctl tenant get acme
hjctl tenant update acme --name "ACME Corporation"
hjctl tenant get-settings acme
hjctl tenant set-settings acme --file settings.json
hjctl tenant export acme > acme-backup.json
hjctl tenant import --file acme-backup.json
hjctl tenant stats acme
hjctl tenant rotate-keys acme
hjctl tenant disable acme
hjctl tenant delete acme
```

---

### user

Manage users within a tenant. Requires `--tenant` (or `HELLOJOHN_DEFAULT_TENANT`).

```
hjctl user <subcommand> --tenant <slug>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List users in the tenant. |
| `get <user-id>` | Get user details by UUID. |
| `create` | Create a new user. |
| `update <user-id>` | Update a user's name or email. |
| `delete <user-id>` | Delete a user. **Irreversible.** |
| `disable <user-id>` | Disable a user account (blocks login). |
| `enable <user-id>` | Re-enable a disabled user account. |
| `set-password <user-id>` | Set a new password (admin override, no current password required). |
| `list-roles <user-id>` | List roles assigned to a user. |
| `assign-role <user-id>` | Assign a role to a user. |
| `remove-role <user-id>` | Remove a role from a user. |

**Flags for `create`:**

| Flag | Required | Description |
|------|----------|-------------|
| `--email` | Yes | User's email address. |
| `--password` | Yes | Initial password. |
| `--name` | No | Display name. |

**Examples:**

```bash
hjctl user list --tenant acme
hjctl user create --tenant acme --email alice@acme.com --password s3cr3t --name "Alice"
hjctl user get --tenant acme abc123-uuid
hjctl user disable --tenant acme abc123-uuid
hjctl user set-password --tenant acme abc123-uuid --password newpass
hjctl user assign-role --tenant acme abc123-uuid --role editor
hjctl user list-roles --tenant acme abc123-uuid
```

---

### client

Manage OAuth 2.0 clients within a tenant. Requires `--tenant`.

```
hjctl client <subcommand> --tenant <slug>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List all OAuth clients. |
| `get <client-id>` | Get client details by ID. |
| `create` | Create a new OAuth client. |
| `update <client-id>` | Update a client's name or redirect URIs. |
| `delete <client-id>` | Delete a client. |
| `revoke-secret <client-id>` | Revoke the current client secret and generate a new one. |

**Flags for `create`:**

| Flag | Required | Description |
|------|----------|-------------|
| `--name` | Yes | Display name for the client. |
| `--type` | Yes | `public` or `confidential`. |
| `--redirect-uris` | No | Comma-separated list of allowed redirect URIs. |

**Examples:**

```bash
hjctl client list --tenant acme
hjctl client create --tenant acme --name "My App" --type confidential --redirect-uris "https://app.com/cb"
hjctl client get --tenant acme client-id-here
hjctl client revoke-secret --tenant acme client-id-here
hjctl client delete --tenant acme client-id-here
```

---

### scope

Manage OAuth 2.0 scopes within a tenant. Requires `--tenant`.

```
hjctl scope <subcommand> --tenant <slug>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List all scopes. |
| `get <name>` | Get a scope by name. |
| `create` | Create a new scope. |
| `delete <name>` | Delete a scope. |

**Examples:**

```bash
hjctl scope list --tenant acme
hjctl scope create --tenant acme --name "reports:read" --description "Read access to reports"
hjctl scope get --tenant acme "reports:read"
hjctl scope delete --tenant acme "reports:read"
```

---

### role

Manage RBAC roles within a tenant. Requires `--tenant`.

```
hjctl role <subcommand> --tenant <slug>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List all roles. |
| `get <name>` | Get role details, including permissions. |
| `create <name>` | Create a new role. |
| `update <name>` | Update a role's description or permissions. |
| `delete <name>` | Delete a role. System roles cannot be deleted. |

**Flags for `create`:**

| Flag | Required | Description |
|------|----------|-------------|
| `--description` | No | Human-readable description. |
| `--permissions` | No | Comma-separated list of permissions (e.g. `users:read,users:write`). |

**Examples:**

```bash
hjctl role list --tenant acme
hjctl role create acme editor --permissions "users:read,reports:write"
hjctl role update acme editor --permissions "users:read,reports:read,reports:write"
hjctl role get --tenant acme editor
hjctl role delete --tenant acme editor
```

---

### key

Manage JWT signing keys within a tenant. Requires `--tenant`.

```
hjctl key <subcommand> --tenant <slug>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List signing keys (active and rotated). |
| `rotate` | Trigger key rotation. Old tokens remain valid during the grace period. |

**Examples:**

```bash
hjctl key list --tenant acme
hjctl key rotate --tenant acme
```

---

### audit

View and manage audit log entries within a tenant. Requires `--tenant`.

```
hjctl audit <subcommand> --tenant <slug>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List audit log entries (newest first). |
| `get <id>` | Get a specific audit log entry by ID. |
| `purge` | Delete audit log entries (optionally before a given date). |

**Flags for `purge`:**

| Flag | Required | Description |
|------|----------|-------------|
| `--before` | No | ISO 8601 date. Purge entries before this date. Omit to purge all. |

**Examples:**

```bash
hjctl audit list --tenant acme
hjctl audit get --tenant acme audit-entry-uuid
hjctl audit purge --tenant acme --before 2025-01-01
```

---

### system

System health and diagnostics. Does **not** require `--tenant`.

```
hjctl system <subcommand>
```

| Subcommand | Description |
|------------|-------------|
| `health` | Check server health (HTTP liveness). |
| `ready` | Check server readiness (dependencies up). |
| `cluster` | Get cluster node status (HA mode). |

**Examples:**

```bash
hjctl system health
hjctl system ready
hjctl system cluster
```

---

### webhook

Manage outbound webhook endpoints within a tenant. Requires `--tenant`.

```
hjctl webhook <subcommand> --tenant <slug>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List registered webhook endpoints. |
| `create` | Register a new webhook endpoint. |
| `delete <id>` | Delete a webhook endpoint. |
| `test <id>` | Send a test event to a webhook to verify connectivity. |

**Flags for `create`:**

| Flag | Required | Description |
|------|----------|-------------|
| `--url` | Yes | HTTPS destination URL. |
| `--events` | No | Comma-separated event types to subscribe to (e.g. `user.created,user.deleted`). |
| `--secret` | No | Signing secret for HMAC verification. |

**Examples:**

```bash
hjctl webhook list --tenant acme
hjctl webhook create --tenant acme --url https://app.com/hooks/hj --events "user.created,user.deleted"
hjctl webhook test --tenant acme webhook-uuid
hjctl webhook delete --tenant acme webhook-uuid
```

---

### session

Manage active user sessions within a tenant. Requires `--tenant`.

```
hjctl session <subcommand> --tenant <slug>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List active sessions. |
| `revoke <session-id>` | Revoke a specific session by ID. |
| `revoke-all` | Revoke all active sessions for the tenant. |

**Examples:**

```bash
hjctl session list --tenant acme
hjctl session revoke --tenant acme session-uuid
hjctl session revoke-all --tenant acme
```

---

### mfa

Manage MFA (Multi-Factor Authentication) configuration within a tenant. Requires `--tenant`.

```
hjctl mfa <subcommand> --tenant <slug>
```

| Subcommand | Description |
|------------|-------------|
| `status` | Get the current MFA status for the tenant. |
| `config` | Get the full MFA configuration. |
| `enforce` | Enable or disable the MFA requirement for all users in the tenant. |
| `reset <user-id>` | Reset MFA for a specific user (removes their enrolled devices). |

**Flags for `enforce`:**

| Flag | Required | Description |
|------|----------|-------------|
| `--enabled` | Yes | `true` to require MFA, `false` to make it optional. |

**Examples:**

```bash
hjctl mfa status --tenant acme
hjctl mfa config --tenant acme
hjctl mfa enforce --tenant acme --enabled true
hjctl mfa reset --tenant acme user-uuid
```

---

### token

Manage active OAuth tokens within a tenant. Requires `--tenant`.

```
hjctl token <subcommand> --tenant <slug>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List active (non-revoked) tokens. |
| `revoke <token-id>` | Revoke a token by ID. |

**Examples:**

```bash
hjctl token list --tenant acme
hjctl token revoke --tenant acme token-uuid
```

---

### consent

Manage OAuth consent grants within a tenant. Requires `--tenant`.

```
hjctl consent <subcommand> --tenant <slug>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List granted consent records. |
| `revoke <consent-id>` | Revoke a consent grant. |

**Examples:**

```bash
hjctl consent list --tenant acme
hjctl consent revoke --tenant acme consent-uuid
```

---

### claim

Manage custom JWT claims within a tenant. Requires `--tenant`.

```
hjctl claim <subcommand> --tenant <slug>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List configured custom claims for the tenant. |

**Examples:**

```bash
hjctl claim list --tenant acme
```

---

### invitation

Manage user invitations within a tenant. Requires `--tenant`.

```
hjctl invitation <subcommand> --tenant <slug>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List pending invitations. |
| `create` | Invite a user by email. |
| `resend <id>` | Resend the invitation email. |
| `delete <id>` | Delete a pending invitation. |

**Flags for `create`:**

| Flag | Required | Description |
|------|----------|-------------|
| `--email` | Yes | Email address to invite. |
| `--role` | No | Role to automatically assign upon acceptance. |
| `--expires-in` | No | Invitation expiration duration (e.g. `48h`). |

**Examples:**

```bash
hjctl invitation list --tenant acme
hjctl invitation create --tenant acme --email bob@acme.com --role editor
hjctl invitation resend --tenant acme invitation-uuid
hjctl invitation delete --tenant acme invitation-uuid
```

---

### mcp

Start the integrated MCP (Model Context Protocol) server, which exposes all HelloJohn admin operations as tools for AI agents.

```
hjctl mcp <subcommand>
```

| Subcommand | Description |
|------------|-------------|
| `serve` | Start the MCP server (stdio by default, or HTTP SSE with `--port`). |
| `capabilities` | List all available MCP tools without starting the server. |

**Flags for `serve`:**

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `0` | If > 0, start an HTTP SSE server on `127.0.0.1:<port>` instead of stdio. |
| `--base-url` | from config | HelloJohn server URL. |
| `--api-key` | from config | API key for the MCP server to use. |

**Examples:**

```bash
# stdio mode (for Claude Desktop, Cursor, etc.)
hjctl mcp serve --base-url http://localhost:8080 --api-key hj_admin_...

# SSE mode (for HTTP-based agents)
hjctl mcp serve --port 9000

# List available tools
hjctl mcp capabilities
```

For the MCP server documentation (integration guide, full tool reference, and Claude Desktop config), see [`internal/mcp/README.md`](../../internal/mcp/README.md).

---

### local

Manage a local HelloJohn instance — start/stop the server process, connect it to the
HelloJohn Cloud relay tunnel, and manage the environment profile that holds its
configuration.

All data is stored under `~/.hellojohn/`:

```
~/.hellojohn/
├── env/
│   └── default.env          # Profile env file (edit via hjctl local env)
├── run/
│   ├── hellojohn.pid        # Server PID
│   ├── state.json           # Server state (port, uptime, profile)
│   ├── hellojohn.log        # Server stdout/stderr
│   ├── tunnel.pid           # Tunnel worker PID
│   ├── tunnel.state.json    # Tunnel state (connected, cloud URL)
│   └── tunnel.log           # Tunnel worker stdout/stderr
└── bin/
    └── hellojohn            # Optional: place binary here for auto-discovery
```

#### Quickstart

```bash
# 1. Create a profile with auto-generated keys
hjctl local init

# 2. Review / edit generated values
hjctl local env list

# 3. Start the server in the background
hjctl local start

# 4. Connect to HelloJohn Cloud (optional)
hjctl local connect --token hjtun_your_token_here

# 5. Check everything
hjctl local status
```

---

#### `hjctl local init`

Create the profile env file (`~/.hellojohn/env/default.env`) with auto-generated
`SIGNING_MASTER_KEY` and `SECRETBOX_MASTER_KEY`. Safe to re-run with `--force` if
you want to reset credentials.

```
hjctl local init [--profile <name>] [--force]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--profile` | `default` | Profile name (alphanumeric, hyphens; no spaces or colons). |
| `--force` | `false` | Overwrite an existing profile file. |

**Examples:**

```bash
hjctl local init
hjctl local init --profile staging
hjctl local init --force           # reset default profile
```

---

#### `hjctl local start`

Start the `hellojohn` server as a background process. Waits up to ~8 s for the
health endpoint to respond before returning.

```
hjctl local start [--profile <name>] [--port <n>] [--foreground]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--profile` | `default` | Profile to load env vars from. |
| `--port` | from `BASE_URL` | Override the server port. |
| `--foreground` | `false` | Run in the foreground (blocks the terminal; Ctrl+C to stop). |

**Examples:**

```bash
hjctl local start
hjctl local start --port 9090
hjctl local start --foreground     # attach to terminal
```

---

#### `hjctl local stop`

Stop running processes. Sends SIGTERM → waits 5 s → SIGKILL if needed.

```
hjctl local stop [--server-only] [--tunnel-only]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server-only` | `false` | Stop only the server (leave tunnel running). |
| `--tunnel-only` | `false` | Stop only the tunnel (leave server running). |

> **Tip:** To stop just the tunnel interactively, prefer `hjctl local tunnel stop` —
> it is the canonical path and lives in the same command group as `status` and `logs`.
> `--tunnel-only` is useful in scripts.

**Examples:**

```bash
hjctl local stop                   # stop everything
hjctl local stop --server-only
hjctl local stop --tunnel-only     # scripting shorthand; see also: hjctl local tunnel stop
```

---

#### `hjctl local status`

Show a unified view of the server and tunnel.

```
hjctl local status [--profile <name>]
```

**Sample output:**

```
Local runtime status (profile: default)
  Server : running (pid 12345) - http://localhost:8080 - healthy
  Tunnel : connected (pid 12346)
```

---

#### `hjctl local logs`

Stream the server log file.

```
hjctl local logs [--tail <n>] [--follow] [--profile <name>]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--tail` | `200` | Lines to show from the end of the file. |
| `--follow` | `false` | Keep streaming new lines (Ctrl+C to stop). |

**Examples:**

```bash
hjctl local logs
hjctl local logs --tail 50 --follow
```

---

#### `hjctl local connect`

Connect the local server to the HelloJohn Cloud relay tunnel. The tunnel runs as a
background worker (`_tunnel-worker`) that opens an outbound WebSocket to the cloud
relay — no inbound firewall rules or port forwarding required.

```
hjctl local connect [--token <hjtun_...>] [--cloud-url <url>] [--base-url <url>] [--profile <name>]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--token` | from profile / `HELLOJOHN_TUNNEL_TOKEN` | Tunnel token (starts with `hjtun_`). Required. |
| `--cloud-url` | from profile / `HELLOJOHN_CLOUD_URL` | HelloJohn Cloud URL. Required. |
| `--base-url` | `http://localhost:8080` | Local server URL the tunnel forwards to. |
| `--profile` | `default` | Profile to read settings from. |

**Token resolution order** (first non-empty wins):

1. `--token` flag
2. `HELLOJOHN_TUNNEL_TOKEN` in the profile env file
3. `HELLOJOHN_TUNNEL_TOKEN` OS environment variable

**Examples:**

```bash
# Token stored in profile (recommended)
hjctl local env set HELLOJOHN_TUNNEL_TOKEN=hjtun_...
hjctl local env set HELLOJOHN_CLOUD_URL=https://cloud.hellojohn.com
hjctl local connect

# One-off with flags
hjctl local connect --token hjtun_... --cloud-url https://cloud.hellojohn.com

# Custom local port
hjctl local connect --base-url http://localhost:9090
```

After connecting, the command waits up to 5 s for the worker to confirm the
WebSocket is established, then prints the PID and suggests next steps.

---

#### `hjctl local tunnel`

Manage the running tunnel worker. This is the primary interface for checking
status, reading logs, and stopping the tunnel.

```
hjctl local tunnel <subcommand>
```

| Subcommand | Description |
|------------|-------------|
| `status` | Show tunnel status, uptime, cloud URL, and token prefix. |
| `stop` | Gracefully stop the tunnel worker. **Primary stop path.** |
| `logs` | Stream the tunnel log file. |

##### `hjctl local tunnel status`

```bash
hjctl local tunnel status
```

**Sample output:**

```
Tunnel: connected
  PID: 12346
  Uptime: 3m42s
  Cloud URL: https://cloud.hellojohn.com
  Token Prefix: hjtun_abc12
```

When the worker is running but WebSocket is reconnecting:

```
Tunnel: running (reconnecting)
  PID: 12346
  Uptime: 12s
```

##### `hjctl local tunnel stop`

Gracefully stops the tunnel worker. Sends SIGTERM, waits up to 5 s, then SIGKILL.

```bash
hjctl local tunnel stop
```

##### `hjctl local tunnel logs`

```
hjctl local tunnel logs [--tail <n>] [--follow]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--tail` | `200` | Lines to show from the end of the file. |
| `--follow` | `false` | Keep streaming new lines (Ctrl+C to stop). |

**Examples:**

```bash
hjctl local tunnel logs
hjctl local tunnel logs --tail 50 --follow
```

---

#### `hjctl local env`

Read and write the profile env file without opening it manually. Supports comments,
preserves file order, and redacts sensitive keys in list output.

```
hjctl local env <subcommand> [--profile <name>]
```

| Subcommand | Description |
|------------|-------------|
| `list` | Print all key/value pairs (sensitive values redacted). |
| `get <KEY>` | Print the value of a single key. |
| `set <KEY>=<VALUE>` | Set or update a key. Uncomments the line if it was commented out. |
| `unset <KEY>` | Remove a key from the file entirely. |
| `edit` | Open the env file in `$EDITOR` / `$VISUAL` (falls back to `nano` or `vi`). |
| `validate` | Check that required keys are present and valid. |

**Key rules:**
- Format: `[A-Za-z_][A-Za-z0-9_]*` (standard env variable names).
- Values are stored verbatim — leading/trailing spaces are preserved.
- Sensitive keys (`*_KEY`, `*_TOKEN`, `*_SECRET`, values starting with `hjtun_`) are
  redacted in `list` output. Use `--reveal` on `get` to see the raw value.

**Profile name rules:**
- Alphanumeric characters, hyphens, and underscores only.
- No spaces, colons, path separators, or `..` sequences.

**Examples:**

```bash
# View all settings
hjctl local env list

# Read a value
hjctl local env get BASE_URL
hjctl local env get HELLOJOHN_TUNNEL_TOKEN --reveal

# Set values
hjctl local env set BASE_URL=http://localhost:8080
hjctl local env set HELLOJOHN_TUNNEL_TOKEN=hjtun_live_token_here
hjctl local env set HELLOJOHN_CLOUD_URL=https://cloud.hellojohn.com

# Remove a key
hjctl local env unset HELLOJOHN_TUNNEL_TOKEN

# Open in editor
hjctl local env edit

# Check required keys are set
hjctl local env validate
```

**Profile env file format** (`~/.hellojohn/env/default.env`):

```bash
# Generated by hjctl local init
SIGNING_MASTER_KEY=<64-char hex>
SECRETBOX_MASTER_KEY=<base64-32-bytes>
APP_ENV=dev
BASE_URL=http://localhost:8080

# Cloud tunnel (uncomment to use)
# HELLOJOHN_CLOUD_URL=https://cloud.hellojohn.com
# HELLOJOHN_TUNNEL_TOKEN=hjtun_...
```

The file uses standard `.env` syntax: `KEY=VALUE` pairs, `#` for comments. Lines
that are commented out (starting with `#`) are activated automatically when you
`set` that key.

---

#### Tunnel architecture

The tunnel uses an outbound WebSocket to the HelloJohn Cloud relay — the local
machine opens the connection, so **no inbound firewall rules or port forwarding are
needed**.

```
Browser / Cloud Panel
        │  HTTP request
        ▼
HelloJohn Cloud (relay WebSocket server)
        │  frames over WebSocket
        ▼
_tunnel-worker (outbound WebSocket client, runs locally)
        │  HTTP forward
        ▼
hellojohn (local server, http://localhost:8080)
        │  HTTP response
        ▲─────────────────────────────────────────
```

The worker:
- Reconnects automatically with exponential back-off (1 s → 30 s max) on disconnect.
- Forwards requests concurrently (each request runs in its own goroutine, response is
  enqueued back over a single write channel to avoid WebSocket frame interleaving).
- Updates `tunnel.state.json` on connect/disconnect, which `status` reads.
- The tunnel token (`hjtun_...`) is passed to the worker via environment variable,
  never via command-line arguments (not visible in `ps aux`).

---

#### Environment variables for local runtime

| Variable | Description |
|----------|-------------|
| `HELLOJOHN_TUNNEL_TOKEN` | Tunnel token issued by HelloJohn Cloud. Starts with `hjtun_`. |
| `HELLOJOHN_CLOUD_URL` | HelloJohn Cloud base URL (e.g. `https://cloud.hellojohn.com`). |
| `BASE_URL` | Backend base URL — used as the OIDC issuer and in email links. |
| `SIGNING_MASTER_KEY` | JWT signing master key (hex, 64 chars). Auto-generated by `init`. |
| `SECRETBOX_MASTER_KEY` | Encryption key for secrets at rest (base64, 32 bytes). Auto-generated. |

All other standard HelloJohn env vars (`APP_ENV`, `CORS_ORIGINS`, `FS_ROOT`, etc.)
are also supported in the profile file — see the [Configuration](#configuration)
section in the main README.

---

## Examples

### Bootstrap a new instance

```bash
# 1. Authenticate with the first admin API key
hjctl auth login --base-url http://localhost:8080 --api-key hj_admin_<your-key>

# 2. Create a tenant
hjctl tenant create --slug demo --name "Demo Corp"

# 3. Add a test user
hjctl user create --tenant demo --email test@demo.com --password changeme --name "Test User"

# 4. Create an OAuth client
hjctl client create --tenant demo --name "Web App" --type confidential \
  --redirect-uris "http://localhost:3000/callback"

# 5. Check everything is working
hjctl system health
hjctl tenant stats demo
```

### Rotate API keys (CI/CD automation)

```bash
# Rotate the CI key and save the new token
NEW_TOKEN=$(hjctl api-key rotate $CI_KEY_ID -o json | jq -r '.new_key.token')
echo "New token: $NEW_TOKEN"
```

### Bulk user management via JSON

```bash
# Export current state
hjctl user list --tenant acme -o json > users.json

# Set password for a specific user
hjctl user set-password --tenant acme $USER_UUID --password $(openssl rand -base64 16)
```

### Revoke all sessions after a security incident

```bash
hjctl session revoke-all --tenant acme
echo "All sessions revoked for tenant acme."
```

### Run a local instance and connect it to the cloud tunnel

```bash
# First time: initialise a profile (generates keys automatically)
hjctl local init

# Store tunnel settings in the profile so you never pass flags again
hjctl local env set HELLOJOHN_CLOUD_URL=https://cloud.hellojohn.com
hjctl local env set HELLOJOHN_TUNNEL_TOKEN=hjtun_...

# Start the server
hjctl local start

# Connect to the cloud relay
hjctl local connect

# Check everything at a glance
hjctl local status

# Follow tunnel logs
hjctl local tunnel logs --follow

# Stop just the tunnel
hjctl local tunnel stop

# Stop everything
hjctl local stop
```

### Scripted CI setup (headless)

```bash
# Start server and verify health before running tests
hjctl local start
hjctl local status

# Run your test suite
go test ./...

# Teardown
hjctl local stop
```
