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
