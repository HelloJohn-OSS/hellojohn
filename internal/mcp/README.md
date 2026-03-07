# HelloJohn MCP Server

The HelloJohn MCP server exposes the full admin API as **tools** for AI agents using the [Model Context Protocol](https://modelcontextprotocol.io). This allows agents like Claude, Cursor, and other MCP-compatible tools to manage tenants, users, clients, API keys, roles, webhooks, and more — using natural language.

---

## Table of Contents

- [What Is the MCP Server?](#what-is-the-mcp-server)
- [Transport Modes](#transport-modes)
- [Setup](#setup)
  - [Claude Desktop](#claude-desktop)
  - [Cursor](#cursor)
  - [SSE (HTTP) Mode](#sse-http-mode)
- [Authentication](#authentication)
- [Tools Reference](#tools-reference)
  - [Tenant Tools](#tenant-tools)
  - [User Tools](#user-tools)
  - [OAuth Client Tools](#oauth-client-tools)
  - [API Key Tools](#api-key-tools)
  - [Scope Tools](#scope-tools)
  - [Role Tools](#role-tools)
  - [Session Tools](#session-tools)
  - [Webhook Tools](#webhook-tools)
  - [System Tools](#system-tools)
- [Security Considerations](#security-considerations)
- [Architecture](#architecture)

---

## What Is the MCP Server?

The MCP server is a bridge between AI agents and the HelloJohn admin API. Instead of writing scripts or using the REST API directly, you can ask an AI agent (in plain language) to:

- *"Create a tenant called acme, then add a user alice@acme.com with the editor role"*
- *"List all expired API keys and revoke them"*
- *"Export the staging tenant and show me its SMTP settings"*

The agent translates these requests into the appropriate tool calls and executes them against your HelloJohn instance.

**Total available tools: 46**

---

## Transport Modes

The MCP server supports two transport modes:

| Mode | Flag | Use case |
|------|------|----------|
| **stdio** | (default) | Claude Desktop, Cursor, VS Code extensions — any client that spawns a subprocess. |
| **SSE (HTTP)** | `--port <n>` | HTTP-based agents, CI pipelines, custom integrations. Binds to `127.0.0.1:<port>`. |

---

## Setup

### Prerequisites

1. A running HelloJohn instance
2. An `admin`-scoped API key: `hjctl api-key create --name "MCP Agent" --scope admin`
3. `hjctl` installed and authenticated: `hjctl auth login --base-url ... --api-key ...`

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "hellojohn": {
      "command": "hjctl",
      "args": [
        "mcp", "serve",
        "--base-url", "http://localhost:8080",
        "--api-key", "hj_admin_your_key_here"
      ]
    }
  }
}
```

Restart Claude Desktop. The HelloJohn tools will appear in the tool list automatically.

### Cursor

In `.cursor/mcp.json` (workspace) or `~/.cursor/mcp.json` (global):

```json
{
  "mcpServers": {
    "hellojohn": {
      "command": "hjctl",
      "args": [
        "mcp", "serve",
        "--base-url", "http://localhost:8080",
        "--api-key", "hj_admin_your_key_here"
      ]
    }
  }
}
```

### SSE (HTTP) Mode

Useful for agents that connect over HTTP rather than spawning a subprocess:

```bash
# Start the SSE server on port 9000
hjctl mcp serve --port 9000 --base-url http://localhost:8080 --api-key hj_admin_...

# The server is accessible at:
# http://127.0.0.1:9000/sse     ← SSE stream (agent connects here)
# http://127.0.0.1:9000/message ← Tool call endpoint
```

> **Note:** The SSE server binds to `127.0.0.1` only (loopback). Do not expose it publicly without a reverse proxy and authentication layer.

### Using Environment Variables

You can use environment variables instead of inline flags to avoid storing keys in config files:

```bash
export HELLOJOHN_BASE_URL=http://localhost:8080
export HELLOJOHN_API_KEY=hj_admin_...
hjctl mcp serve
```

Or in Claude Desktop config:

```json
{
  "mcpServers": {
    "hellojohn": {
      "command": "hjctl",
      "args": ["mcp", "serve"],
      "env": {
        "HELLOJOHN_BASE_URL": "http://localhost:8080",
        "HELLOJOHN_API_KEY": "hj_admin_your_key_here"
      }
    }
  }
}
```

---

## Authentication

The MCP server authenticates to HelloJohn using an API key supplied via `--api-key` (or `HELLOJOHN_API_KEY`). The key must have **admin** scope to use all tools. A **readonly**-scoped key can be used to restrict the agent to read-only operations.

The API key is sent as the `X-API-Key` header on every request to the HelloJohn backend.

---

## Tools Reference

Each tool name follows the pattern `hellojohn_<verb>_<noun>`. Destructive operations are annotated accordingly and will typically require explicit confirmation from the user in interactive agents.

---

### Tenant Tools

| Tool | Description | Destructive |
|------|-------------|-------------|
| `hellojohn_list_tenants` | List all tenants in the HelloJohn instance. | No |
| `hellojohn_get_tenant` | Get details of a specific tenant by slug. | No |
| `hellojohn_create_tenant` | Create a new tenant. | No |
| `hellojohn_update_tenant` | Update a tenant's display name or language. | No |
| `hellojohn_delete_tenant` | Delete a tenant by slug. Cannot be undone. | **Yes** |
| `hellojohn_export_tenant` | Export a tenant's configuration as JSON. | No |
| `hellojohn_get_tenant_settings` | Get the settings for a specific tenant (SMTP, cache, DB, etc.). | No |
| `hellojohn_set_tenant_settings` | Update tenant settings. Provide a JSON object with the fields to update. | No |

**`hellojohn_create_tenant` parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `slug` | Yes | URL-safe unique identifier (e.g. `acme`). |
| `name` | Yes | Display name (e.g. `"ACME Corp"`). |
| `language` | No | Language code, defaults to `en`. |

**`hellojohn_update_tenant` / `hellojohn_get_tenant` / `hellojohn_export_tenant` / `hellojohn_get_tenant_settings` / `hellojohn_delete_tenant` parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `slug` | Yes | Tenant slug. |

**`hellojohn_set_tenant_settings` parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `slug` | Yes | Tenant slug. |
| `settings_json` | Yes | JSON string containing the settings fields to update (e.g. `{"smtp": {"host": "smtp.sendgrid.net"}}`). |

---

### User Tools

| Tool | Description | Destructive |
|------|-------------|-------------|
| `hellojohn_list_users` | List all users in a tenant. | No |
| `hellojohn_get_user` | Get details of a specific user by ID. | No |
| `hellojohn_create_user` | Create a new user in a tenant. | No |
| `hellojohn_update_user` | Update a user's name or email address. | No |
| `hellojohn_disable_user` | Disable a user account (blocks login). | No |
| `hellojohn_enable_user` | Enable a disabled user account. | No |
| `hellojohn_set_user_password` | Set a new password for a user (admin override, bypasses current password check). | No |
| `hellojohn_delete_user` | Delete a user from a tenant. Irreversible. | **Yes** |

**`hellojohn_list_users` parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `tenant` | Yes | Tenant slug. |

**User-specific parameters (all user tools except `list`):**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `tenant` | Yes | Tenant slug. |
| `user_id` | Yes | User UUID. |

**`hellojohn_create_user` additional parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `email` | Yes | User's email address. |
| `password` | Yes | Initial password. |
| `name` | No | Display name. |

**`hellojohn_set_user_password` additional parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `password` | Yes | New password to set. |

---

### OAuth Client Tools

| Tool | Description | Destructive |
|------|-------------|-------------|
| `hellojohn_list_clients` | List all OAuth clients in a tenant. | No |
| `hellojohn_get_client` | Get details of a specific OAuth client. | No |
| `hellojohn_create_client` | Create a new OAuth client in a tenant. | No |
| `hellojohn_update_client` | Update an OAuth client's name or redirect URIs. | No |
| `hellojohn_revoke_client_secret` | Revoke the current client secret and generate a new one. | No |
| `hellojohn_delete_client` | Delete an OAuth client from a tenant. | **Yes** |

**`hellojohn_create_client` parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `tenant` | Yes | Tenant slug. |
| `name` | Yes | Client display name. |
| `type` | Yes | `public` or `confidential`. |
| `redirect_uris` | No | Comma-separated list of allowed redirect URIs. |

**Other client tools parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `tenant` | Yes | Tenant slug. |
| `client_id` | Yes | OAuth client ID. |

---

### API Key Tools

> **Important:** The raw token is only included in the response to `hellojohn_create_api_key` and `hellojohn_rotate_api_key`. It is shown exactly once — instruct the agent to display it clearly and save it immediately.

| Tool | Description | Destructive |
|------|-------------|-------------|
| `hellojohn_list_api_keys` | List all API keys (IDs, names, scopes — never raw tokens or hashes). | No |
| `hellojohn_get_api_key` | Get details of a specific API key by UUID. | No |
| `hellojohn_create_api_key` | Create a new API key. **Token shown once.** | No |
| `hellojohn_revoke_api_key` | Revoke an API key permanently. | **Yes** |
| `hellojohn_rotate_api_key` | Revoke the old key and issue a new one. **New token shown once.** | **Yes** |

**`hellojohn_create_api_key` parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `name` | Yes | Descriptive name for the key. |
| `scope` | Yes | `admin`, `readonly`, or `cloud`. |
| `expires_in` | No | Expiration duration, e.g. `720h`. Omit for no expiration. |

**`hellojohn_get_api_key` / `hellojohn_revoke_api_key` / `hellojohn_rotate_api_key` parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `id` | Yes | API key UUID. |

---

### Scope Tools

| Tool | Description | Destructive |
|------|-------------|-------------|
| `hellojohn_list_scopes` | List all OAuth scopes in a tenant. | No |
| `hellojohn_create_scope` | Create a new OAuth scope in a tenant. | No |
| `hellojohn_delete_scope` | Delete an OAuth scope from a tenant. | **Yes** |

**Parameters for all scope tools:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `tenant` | Yes | Tenant slug. |

**`hellojohn_create_scope` additional parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `name` | Yes | Scope name (e.g. `reports:read`). |
| `description` | No | Human-readable description. |

**`hellojohn_delete_scope` additional parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `name` | Yes | Scope name to delete. |

---

### Role Tools

| Tool | Description | Destructive |
|------|-------------|-------------|
| `hellojohn_list_roles` | List all RBAC roles in a tenant. | No |
| `hellojohn_get_role` | Get details of a specific RBAC role, including its permissions. | No |
| `hellojohn_create_role` | Create a new RBAC role in a tenant. | No |
| `hellojohn_update_role` | Update an RBAC role's description or permissions. | No |
| `hellojohn_delete_role` | Delete an RBAC role from a tenant. System roles cannot be deleted. | **Yes** |

**`hellojohn_create_role` parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `tenant` | Yes | Tenant slug. |
| `name` | Yes | Role name (e.g. `editor`). |
| `description` | No | Human-readable description. |
| `permissions` | No | Comma-separated list of permissions (e.g. `users:read,users:write`). |

**Other role tools parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `tenant` | Yes | Tenant slug. |
| `name` | Yes | Role name. |

---

### Session Tools

| Tool | Description | Destructive |
|------|-------------|-------------|
| `hellojohn_list_sessions` | List active sessions for a tenant. | No |
| `hellojohn_revoke_session` | Revoke a specific session by ID. | **Yes** |
| `hellojohn_revoke_all_sessions` | Revoke all active sessions for a tenant. | **Yes** |

**Parameters:**

| Parameter | Required | Tool |
|-----------|----------|------|
| `tenant` | Yes | All session tools |
| `session_id` | Yes | `hellojohn_revoke_session` only |

---

### Webhook Tools

| Tool | Description | Destructive |
|------|-------------|-------------|
| `hellojohn_list_webhooks` | List webhook endpoints for a tenant. | No |
| `hellojohn_create_webhook` | Register a new webhook endpoint for a tenant. | No |
| `hellojohn_test_webhook` | Send a test event to a webhook endpoint to verify connectivity. | No |
| `hellojohn_delete_webhook` | Delete a webhook endpoint. | **Yes** |

**`hellojohn_create_webhook` parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `tenant` | Yes | Tenant slug. |
| `url` | Yes | HTTPS destination URL. |
| `events` | No | Comma-separated event types (e.g. `user.created,user.deleted`). |
| `secret` | No | HMAC signing secret for payload verification. |

**`hellojohn_test_webhook` / `hellojohn_delete_webhook` parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `tenant` | Yes | Tenant slug. |
| `id` | Yes | Webhook endpoint UUID. |

---

### System Tools

| Tool | Description | Destructive |
|------|-------------|-------------|
| `hellojohn_system_health` | Check if the HelloJohn server is healthy (liveness). | No |
| `hellojohn_system_ready` | Check if the HelloJohn server is ready to serve requests (readiness). | No |
| `hellojohn_list_signing_keys` | List JWT signing keys for a tenant. | No |
| `hellojohn_rotate_signing_key` | Rotate the JWT signing key for a tenant. Old tokens remain valid during the grace period. | No |

**`hellojohn_list_signing_keys` / `hellojohn_rotate_signing_key` parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `tenant` | Yes | Tenant slug. |

---

## Security Considerations

1. **Use a dedicated MCP API key.** Create a key with the minimum required scope. For read-only agents, use `scope: readonly`.

2. **The stdio server inherits process trust.** Any process that can execute `hjctl mcp serve` can call all tools. Protect the binary and the config file (`~/.hjctl/config.yaml`, mode `0600`).

3. **The SSE server binds to loopback only.** `127.0.0.1:<port>` is not accessible from other machines. If you need remote access, use a reverse proxy with authentication in front of it.

4. **Destructive tools require explicit user intent.** In interactive agents (Claude Desktop, Cursor), the agent will typically ask for confirmation before calling destructive tools. Do not disable this behavior.

5. **Do not log API keys.** The `X-API-Key` header is never logged by the MCP server. However, shell history and process listings may expose `--api-key` flag values — prefer environment variables in production.

---

## Architecture

```
AI Agent (Claude, Cursor, etc.)
    │
    │  MCP tool call (JSON-RPC 2.0)
    ▼
hjctl mcp serve  (this package)
    │
    │  HTTP  X-API-Key: hj_admin_...
    ▼
HelloJohn  /v2/admin/...
```

**Package structure:**

| File | Contents |
|------|----------|
| `server.go` | `NewServer()` — instantiates the MCP server and registers all tool groups. |
| `handler.go` | `Handler` — HTTP client that bridges tool calls to the HelloJohn API. |
| `helpers.go` | Shared utilities (`errMissing`, `splitAndTrim`). |
| `tenant_tools.go` | 8 tenant management tools. |
| `user_tools.go` | 8 user management tools. |
| `client_tools.go` | 6 OAuth client tools. |
| `apikey_tools.go` | 5 API key tools. |
| `scope_tools.go` | 3 OAuth scope tools. |
| `role_tools.go` | 5 RBAC role tools. |
| `session_tools.go` | 3 session management tools. |
| `webhook_tools.go` | 4 webhook tools. |
| `system_tools.go` | 4 system/health tools. |

The MCP server is stateless — it holds only the HTTP client configuration (base URL, API key, timeout). All state lives in the HelloJohn backend.
