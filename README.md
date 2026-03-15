# HelloJohn

> **The Developer-First Identity Platform**
>
> A self-hosted, multi-tenant, open-source alternative to Auth0, Clerk and Keycloak.
> Built for developers who want full control without operational complexity.

![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat)
![Status](https://img.shields.io/badge/status-stable-brightgreen?style=flat)

---

## What is HelloJohn?

**HelloJohn** is a modern Identity and Access Management (IAM) platform designed for **true multi-tenancy from day one**. Unlike traditional solutions that share a single database and rely on `tenant_id` column isolation, HelloJohn gives each tenant its own physical database — while the Control Plane runs entirely on the filesystem with **no database required** by default.

It implements the full **OAuth2 + OpenID Connect** specification, supports **9 social providers**, ships **7 SDKs**, and adds production-grade features like WebAuthn/Passkeys, adaptive MFA, RBAC, bot protection, and automatic JWT key rotation.

---

## Key Differentiators

| Feature | HelloJohn | Auth0 / Clerk | Keycloak |
| :--- | :--- | :--- | :--- |
| **Data isolation** | Physical (separate DB per tenant) | Logical (`tenant_id` columns) | Realms (logical) |
| **Control Plane** | FileSystem — no DB required | Central DB | Central DB |
| **DB drivers** | PostgreSQL, MySQL (MongoDB planned) | Proprietary / Cloud | Relational only |
| **Social providers** | 9 (incl. Generic OIDC) | 20+ | 20+ |
| **WebAuthn / Passkeys** | ✅ Native | ✅ | ✅ |
| **Self-hosted cost** | Free | $$$ per MAU | Free (high ops TCO) |
| **SDK coverage** | 7 languages | 10+ | Adapters only |

---

## Features

### Authentication
- **Password auth** with configurable policy (min/max length, complexity rules, breach detection, common password check)
- **Social Login** — Google, GitHub, Microsoft, Discord, Facebook, LinkedIn, Apple, GitLab, Generic OIDC
- **WebAuthn / Passkeys** — browser-native biometric and hardware key authentication (FIDO2)
- **Magic Links** — passwordless email login

### Multi-Factor Authentication (MFA)
- **TOTP** (Time-based One-Time Password) — Google Authenticator, Authy, etc.
- **Email OTP** — configurable length and TTL
- **SMS OTP** — Twilio and Vonage supported
- **Adaptive MFA** — automatically triggers MFA on IP change, device change, or failed attempts

### Standards
- **OAuth2** — Authorization Code (with PKCE), Client Credentials, Refresh Token flows
- **OpenID Connect** — Discovery, JWKS, UserInfo, ID tokens
- **JWT** — EdDSA signing, automatic key rotation, configurable grace period

### Authorization
- **RBAC** — Roles with permissions arrays; roles assigned per user; system roles protected
- **Scopes** — per-client scope definitions
- **Dynamic Claims** — custom JWT claims from user profile fields

### Security
- **Bot Protection** — Cloudflare Turnstile (login, registration, password reset — configurable per endpoint)
- **Rate Limiting** — global rate limiter on all public endpoints
- **CSRF Protection**
- **Session Management** — configurable TTL, Secure flag, SameSite, domain
- **Refresh Token Reuse Detection** (feature flag)
- **ChaCha20-Poly1305** encryption for secrets at rest
- **Argon2id** password hashing

### Infrastructure
- **Control Plane** — FileSystem-based, optional Global DB mode (`GLOBAL_CONTROL_PLANE_DSN`)
- **Data Plane** — per-tenant PostgreSQL or MySQL; connection pool per tenant
- **Cache** — Redis / in-memory, per-tenant
- **System SMTP** — global fallback email service for transactional emails
- **Audit Logging** — structured logs to stdout and file

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      HelloJohn Service                       │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Controllers │→ │   Services   │→ │       DAL        │  │
│  │  (HTTP only) │  │ (Biz Logic)  │  │  (Repos + Cache) │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                              │              │
│  ┌────────────────────────┐  ┌───────────────┴──────────┐   │
│  │     Control Plane      │  │       Data Plane         │   │
│  │  FileSystem (FS_ROOT)  │  │  Per-Tenant DB (PG/MySQL)│   │
│  │  Tenants, Clients,     │  │  Users, Tokens, Sessions │   │
│  │  Scopes, Keys          │  │  MFA, RBAC, Consents     │   │
│  └────────────────────────┘  └──────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Layers

| Layer | Location | Responsibility |
| :--- | :--- | :--- |
| **HTTP** | `internal/http/controllers/` | Parse request, write response — no business logic |
| **Services** | `internal/http/services/` | Business logic — no HTTP dependencies |
| **DAL** | `internal/store/` | Data access abstraction (4 operational modes) |
| **Control Plane** | `internal/controlplane/` | Tenant, client, scope management via FS |
| **JWT** | `internal/jwt/` | EdDSA key management, token issuance/validation |
| **Security** | `internal/security/` | Argon2, TOTP, ChaCha20 encryption |
| **Email** | `internal/email/` | System SMTP + per-tenant SMTP |

### DAL Operational Modes

| Mode | Control Plane | Data Plane | Use Case |
| :--- | :--- | :--- | :--- |
| **FS Only** | FileSystem | None | Development, testing |
| **FS + Tenant DB** | FileSystem | DB per tenant | Standard SaaS |
| **FS + Global DB** | FS + Global DB | None | Config backup / HA |
| **Full DB** | FS + Global DB | DB per tenant | Enterprise |


---

## Quick Start

### Prerequisites

- A PostgreSQL or MySQL database for each tenant (the Control Plane itself needs no DB)
- For Option A: Node.js 18+
- For Option C: Go 1.21+

### Option A — npx (recommended)

No installation required. One command downloads the binaries, generates keys, and starts the server:

```bash
npx hellojohn-oss quickstart
```

Or install globally and run:

```bash
npm install -g hellojohn-oss
hellojohn-oss quickstart
```

See [`hellojohn-npm-installer`](https://github.com/HelloJohn-OSS/hellojohn-npm-installer) for the full reference — commands, flags, air-gapped installs, and troubleshooting.

### Option B — Docker

```bash
docker run \
  -e SIGNING_MASTER_KEY=$(openssl rand -hex 32) \
  -e SECRETBOX_MASTER_KEY=$(openssl rand -base64 32) \
  -e BASE_URL=http://localhost:8080 \
  -e FS_ADMIN_ENABLE=true \
  -p 8080:8080 \
  ghcr.io/dropdatabas3/hellojohn:latest
```

### Option C — Build from source

```bash
git clone https://github.com/HelloJohn-OSS/hellojohn.git
cd hellojohn

# Generate required keys
export SIGNING_MASTER_KEY=$(openssl rand -hex 32)
export SECRETBOX_MASTER_KEY=$(openssl rand -base64 32)

# Run
go run ./cmd/service
```

### Verify

```bash
# Health check
curl http://localhost:8080/health

# OIDC Discovery
curl http://localhost:8080/.well-known/openid-configuration
```

---

## Configuration

All environment variables are read **once at startup** by `internal/http/server/config.go`. Services and controllers receive configuration via dependency injection — no `os.Getenv()` outside of that file.

### Required Keys

| Variable | Description | How to Generate |
| :--- | :--- | :--- |
| `SIGNING_MASTER_KEY` | JWT signing master key (hex, 64 chars) | `openssl rand -hex 32` |
| `SECRETBOX_MASTER_KEY` | Encryption key for secrets at rest (base64, 32 bytes) | `openssl rand -base64 32` |

### System

| Variable | Default | Description |
| :--- | :--- | :--- |
| `APP_ENV` | `dev` | Environment: `dev` \| `staging` \| `prod` |
| `BASE_URL` | `http://localhost:8080` | Backend base URL (used as OIDC issuer and in email links) |
| `UI_BASE_URL` | `http://localhost:3000` | Frontend URL (OAuth consent and login pages) |
| `FS_ROOT` | `data` | Control Plane filesystem root directory |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed CORS origins (comma-separated) |
| `FS_ADMIN_ENABLE` | `false` | Allow self-registration for the first admin user |

### Tokens & Sessions

| Variable | Default | Description |
| :--- | :--- | :--- |
| `REFRESH_TTL` | `720h` | Refresh token TTL (e.g. `720h` = 30 days) |
| `REGISTER_AUTO_LOGIN` | `true` | Automatically issue tokens after registration |
| `SESSION_TTL` | `24h` | Session cookie TTL |
| `SESSION_SECURE` | auto | Secure cookie flag (inferred from `BASE_URL` scheme) |
| `SESSION_SAMESITE` | `Lax` | SameSite policy: `Lax` \| `Strict` \| `None` |
| `SESSION_DOMAIN` | _(empty)_ | Cookie domain (empty = host only) |
| `KEY_ROTATION_GRACE` | `60` | Grace period in seconds after JWT key rotation |

### Global Database (Control Plane — optional)

Activating `GLOBAL_CONTROL_PLANE_DSN` switches the Control Plane from pure filesystem to a hybrid FS + DB mode. Without it, the system runs fully filesystem-based.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `GLOBAL_CONTROL_PLANE_DSN` | _(empty)_ | Global DB connection string. Example: `postgres://user:pass@localhost:5432/hellojohn_cp?sslmode=disable` |
| `GLOBAL_CONTROL_PLANE_DRIVER` | `pg` | Driver: `pg` \| `mysql` |
| `SYNC_DRY_RUN` | `false` | Set to `true` to simulate FS-to-DB migration without writing |

### System SMTP (global email fallback)

Used for system-level transactional emails (admin invites, email verification, password reset). Per-tenant SMTP is configured separately via the tenant settings.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SMTP_HOST` | _(empty)_ | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USER` | _(empty)_ | SMTP username / API key |
| `SMTP_PASSWORD` | _(empty)_ | SMTP password or API key secret |
| `SMTP_FROM` | _(empty)_ | Sender address (e.g. `noreply@example.com`) |


### MFA

| Variable | Default | Description |
| :--- | :--- | :--- |
| `MFA_TOTP_WINDOW` | `1` | TOTP validation window ±N (0–3) |
| `MFA_TOTP_ISSUER` | `HelloJohn` | Display name in authenticator apps |
| `MFA_SMS_PROVIDER` | `twilio` | SMS provider: `twilio` \| `vonage` |
| `MFA_SMS_PHONE_FIELD` | `phone` | User custom field containing E.164 phone number |
| `MFA_SMS_OTP_LENGTH` | `6` | SMS OTP code length |
| `MFA_SMS_OTP_TTL` | `5m` | SMS OTP validity window |
| `MFA_SMS_RATE_LIMIT_HOURLY` | `5` | Max SMS OTP sends per user per hour |
| `MFA_SMS_TWILIO_ACCOUNT_SID` | _(empty)_ | Twilio account SID |
| `MFA_SMS_TWILIO_AUTH_TOKEN` | _(empty)_ | Twilio auth token |
| `MFA_SMS_TWILIO_FROM` | _(empty)_ | Twilio sender phone number |
| `MFA_SMS_VONAGE_API_KEY` | _(empty)_ | Vonage API key |
| `MFA_SMS_VONAGE_API_SECRET` | _(empty)_ | Vonage API secret |
| `MFA_SMS_VONAGE_FROM` | _(empty)_ | Vonage sender phone number |
| `MFA_EMAIL_OTP_LENGTH` | `6` | Email OTP code length |
| `MFA_EMAIL_OTP_TTL` | `5m` | Email OTP validity window |
| `MFA_EMAIL_RATE_LIMIT_HOURLY` | `5` | Max email OTP sends per user per hour |
| `MFA_EMAIL_SUBJECT` | `Your verification code` | Email OTP subject line |
| `MFA_PREFERRED_FACTOR_FIELD` | `mfa_preferred_factor` | User field storing the preferred MFA method |
| `MFA_ADAPTIVE_ENABLED` | `false` | Enable adaptive MFA (auto-challenge on suspicious activity) |
| `MFA_ADAPTIVE_RULES` | `ip_change,ua_change,failed_attempts` | Comma-separated adaptive trigger rules |
| `MFA_ADAPTIVE_FAILURE_THRESHOLD` | `5` | Failed attempts before adaptive MFA triggers |
| `MFA_ADAPTIVE_STATE_TTL` | `720h` | How long adaptive MFA state is remembered |

### Bot Protection (Cloudflare Turnstile)

Get your keys from [Cloudflare Turnstile dashboard](https://dash.cloudflare.com). Leave disabled in development.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `BOT_PROTECTION_ENABLED` | `false` | Enable bot protection globally |
| `BOT_PROTECTION_PROVIDER` | `turnstile` | Provider (only `turnstile` supported) |
| `TURNSTILE_SITE_KEY` | _(empty)_ | Cloudflare Turnstile public site key (sent to frontend) |
| `TURNSTILE_SECRET_KEY` | _(empty)_ | Cloudflare Turnstile secret key (backend validation only) |
| `BOT_PROTECT_LOGIN` | `true` | Require Turnstile token on login |
| `BOT_PROTECT_REGISTRATION` | `true` | Require Turnstile token on registration |
| `BOT_PROTECT_PASSWORD_RESET` | `false` | Require Turnstile token on password reset |

> Per-tenant bot protection config (different site key, custom appearance) can be set via the tenant settings and overrides the global config.

### Admin & Security

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ADMIN_ENFORCE` | `0` | Set to `1` to enable strict admin role check on all admin endpoints |
| `ADMIN_SUBS` | _(empty)_ | Comma-separated user IDs with emergency admin access |

### Feature Flags

| Variable | Default | Description |
| :--- | :--- | :--- |
| `FEATURE_REFRESH_REUSE_DETECTION` | `false` | Detect and reject reused refresh tokens (replay attack protection) |
| `FEATURE_SESSION_TOKEN` | `true` | Enable `/v2/session/token` endpoint |
| `FEATURE_CLIENT_PROFILES` | `true` | Enforce grant type compatibility by OAuth client profile |
| `FEATURE_HOST_COOKIE` | `true` | Use `__Host-` cookie prefix when conditions are met |

### Audit Logging

| Variable | Default | Description |
| :--- | :--- | :--- |
| `AUDIT_STDOUT_ENABLED` | `true` | Write audit events to stdout (recommended: `false` in production) |
| `AUDIT_CONTROLPLANE_LOG_PATH` | `data/controlplane/audit.log` | Control plane audit log file path |
| `AUDIT_OVERFLOW_LOG_PATH` | `data/controlplane/audit-overflow.log` | Overflow log path when main log is at capacity |


---

## API Reference

All endpoints are prefixed with `/v2/`. The service also exposes standard OIDC discovery endpoints at their conventional paths.

### Authentication

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/v2/auth/login` | Password login — returns access + refresh token |
| `POST` | `/v2/auth/register` | User registration |
| `POST` | `/v2/auth/refresh` | Refresh access token |
| `POST` | `/v2/auth/logout` | Invalidate session and refresh token |
| `POST` | `/v2/auth/forgot` | Request password reset email |
| `POST` | `/v2/auth/reset-password` | Set new password via reset token |
| `GET` | `/v2/auth/verify-email` | Confirm email address via token |
| `GET` | `/v2/auth/config` | Public tenant config (branding, social providers, bot protection site key) |
| `GET` | `/v2/auth/password-policy` | Active password policy for tenant |

### Social Login

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/v2/auth/social/{provider}/start` | Initiate social OAuth flow (redirects to provider) |
| `GET` | `/v2/auth/social/{provider}/callback` | Handle provider callback |
| `POST` | `/v2/auth/social/exchange` | Exchange short-lived code for tokens (PKCE apps) |

Supported providers: `google`, `github`, `microsoft`, `discord`, `facebook`, `linkedin`, `apple`, `gitlab`, `oidc`

### WebAuthn / Passkeys

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/v2/auth/webauthn/register/begin` | Start passkey registration ceremony |
| `POST` | `/v2/auth/webauthn/register/finish` | Complete passkey registration |
| `POST` | `/v2/auth/webauthn/login/begin` | Start passkey authentication ceremony |
| `POST` | `/v2/auth/webauthn/login/finish` | Complete passkey authentication |

### MFA

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/v2/auth/mfa/totp/enroll` | Generate TOTP secret and QR code |
| `POST` | `/v2/auth/mfa/totp/verify` | Verify TOTP code and activate |
| `POST` | `/v2/auth/mfa/totp/disable` | Disable TOTP for user |
| `POST` | `/v2/auth/mfa/email/send` | Send email OTP |
| `POST` | `/v2/auth/mfa/email/verify` | Verify email OTP |
| `POST` | `/v2/auth/mfa/sms/send` | Send SMS OTP |
| `POST` | `/v2/auth/mfa/sms/verify` | Verify SMS OTP |
| `POST` | `/v2/mfa/challenge` | Submit MFA challenge during login flow |

### OAuth2

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/oauth2/authorize` | Authorization endpoint |
| `POST` | `/oauth2/token` | Token exchange (all grant types) |
| `POST` | `/oauth2/revoke` | Revoke access or refresh token |
| `GET` | `/oauth2/consent` | Render consent page |
| `POST` | `/oauth2/consent` | Submit consent decision |

### OIDC

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/.well-known/openid-configuration` | OIDC Discovery document |
| `GET` | `/.well-known/jwks.json` | JSON Web Key Set (public keys) |
| `GET` | `/userinfo` | Authenticated user claims |

### Session

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/v2/session` | Current session info |
| `GET` | `/v2/session/token` | Exchange session cookie for access token |
| `DELETE` | `/v2/session` | Destroy current session |

### Admin — Tenants

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/v2/admin/tenants` | List all tenants |
| `POST` | `/v2/admin/tenants` | Create tenant |
| `GET` | `/v2/admin/tenants/{tenant_id}` | Get tenant details |
| `PUT` | `/v2/admin/tenants/{tenant_id}` | Update tenant config |
| `DELETE` | `/v2/admin/tenants/{tenant_id}` | Delete tenant |

### Admin — Clients (OAuth Applications)

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/v2/admin/tenants/{tenant_id}/clients` | List clients |
| `POST` | `/v2/admin/tenants/{tenant_id}/clients` | Create client |
| `GET` | `/v2/admin/tenants/{tenant_id}/clients/{client_id}` | Get client |
| `PUT` | `/v2/admin/tenants/{tenant_id}/clients/{client_id}` | Update client |
| `DELETE` | `/v2/admin/tenants/{tenant_id}/clients/{client_id}` | Delete client |
| `POST` | `/v2/admin/tenants/{tenant_id}/clients/{client_id}/rotate-secret` | Rotate client secret |

### Admin — Users

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/v2/admin/tenants/{tenant_id}/users` | List users (paginated, filterable) |
| `POST` | `/v2/admin/tenants/{tenant_id}/users` | Create user |
| `GET` | `/v2/admin/tenants/{tenant_id}/users/{user_id}` | Get user |
| `PUT` | `/v2/admin/tenants/{tenant_id}/users/{user_id}` | Update user |
| `DELETE` | `/v2/admin/tenants/{tenant_id}/users/{user_id}` | Delete user |
| `POST` | `/v2/admin/tenants/{tenant_id}/users/{user_id}/block` | Block/unblock user |

### Admin — RBAC

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/v2/admin/tenants/{tenant_id}/roles` | List roles |
| `POST` | `/v2/admin/tenants/{tenant_id}/roles` | Create role |
| `PUT` | `/v2/admin/tenants/{tenant_id}/roles/{role_name}` | Update role |
| `DELETE` | `/v2/admin/tenants/{tenant_id}/roles/{role_name}` | Delete role |
| `POST` | `/v2/admin/tenants/{tenant_id}/roles/{role_name}/permissions` | Add permission to role |
| `DELETE` | `/v2/admin/tenants/{tenant_id}/roles/{role_name}/permissions/{perm}` | Remove permission |
| `POST` | `/v2/admin/tenants/{tenant_id}/users/{user_id}/roles` | Assign role to user |
| `DELETE` | `/v2/admin/tenants/{tenant_id}/users/{user_id}/roles/{role_name}` | Remove role from user |

### Admin — System

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/v2/admin/me` | Current admin user info |
| `POST` | `/v2/admin/register` | Register first admin (requires `FS_ADMIN_ENABLE=true`) |
| `POST` | `/v2/admin/login` | Admin login |
| `GET` | `/health` | Service health check |


---

## API Keys

API keys are long-lived credentials for server-to-server access to the admin API. Unlike JWT access tokens (short-lived, user-bound), API keys are static tokens you create once and inject into services or scripts.

### Scopes

| Scope | Token prefix | Access |
| :--- | :--- | :--- |
| `admin` | `hj_admin_` | Full admin API — tenants, users, clients, roles, keys |
| `readonly` | `hj_ro_` | Read-only access to the admin API |
| `cloud` | `hj_cloud_` | Authorizes the HelloJohn Cloud proxy to forward requests to this instance |
| `tenant:{slug}` | `hj_t_{slug}_` | Scoped to a single tenant's admin endpoints |

### Creating a key

**Via hjctl (recommended):**

```bash
# Log in first
hjctl auth login

# Create an admin key
hjctl api-key create --name "my-service" --scope admin

# Create a cloud key (for cloud proxy connection)
hjctl api-key create --name "cloud-proxy" --scope cloud

# Create a read-only key with expiration
hjctl api-key create --name "monitoring" --scope readonly --expires-in 720h
```

> The raw token is shown **once** at creation time. Save it immediately — it cannot be retrieved afterwards.

**Via API:**

```bash
curl -X POST https://auth.example.com/v2/admin/api-keys \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-service", "scope": "admin"}'
```

### Using a key

Pass the key in the `X-API-Key` header on any admin API request:

```bash
curl https://auth.example.com/v2/admin/tenants \
  -H "X-API-Key: hj_admin_xxxxxxxxxxxx"
```

### Cloud proxy connection

When you register a self-hosted instance in HelloJohn Cloud, the cloud panel proxies admin requests to your instance on your behalf. This proxy authenticates using a `cloud`-scoped API key stored encrypted in the cloud.

```bash
# 1. Create the cloud-scoped key on your instance
hjctl api-key create --name "hellojohn-cloud" --scope cloud
# → prints: hj_cloud_xxxxxxxxxxxx  (save this)

# 2. Register your instance in HelloJohn Cloud and paste the key
#    Settings → Instances → Add Instance → API Key
```

When `hjctl local start` is used with tunnel mode, the API key is **auto-provisioned** — `hjctl` logs in with your profile credentials, creates an `admin`-scoped key, and saves it to `~/.hjctl/config.yaml`. The tunnel worker then injects it automatically on every forwarded request.

### Managing keys

```bash
hjctl api-key list                   # List all keys
hjctl api-key get <id>               # Get key details
hjctl api-key rotate --force <id>    # Rotate (invalidates old key immediately)
hjctl api-key revoke --force <id>    # Permanently revoke
```

---

## SDKs

All SDKs live in [`HelloJohn-OSS/SDKs`](https://github.com/HelloJohn-OSS/SDKs) and target `/v2/*` API routes.

| SDK | Package | Platform | Status |
| :--- | :--- | :--- | :--- |
| JavaScript | `@hellojohn/js` | Browser (framework-agnostic) | ✅ Stable |
| React | `@hellojohn/react` | React 18+, Next.js | ✅ Stable |
| Vue | `@hellojohn/vue` | Vue 3, Nuxt 3 | ✅ Stable |
| React Native | `@hellojohn/react-native` | Expo, RN 0.73+ | ✅ Stable |
| Node.js | `@hellojohn/node` | Express, Fastify, Node APIs | ✅ Stable |
| Go | `github.com/HelloJohn-OSS/SDKs/go` | Go 1.21+ | ✅ Stable |
| Python | `hellojohn` (PyPI) | FastAPI, Flask, Python 3.10+ | ✅ Stable |

### Quickstart Examples

**React**
```tsx
import { AuthProvider, useAuth } from "@hellojohn/react"

function App() {
  const { isAuthenticated, user, signIn, signOut } = useAuth()
  return isAuthenticated ? (
    <button onClick={signOut}>Sign out {user.name}</button>
  ) : (
    <button onClick={signIn}>Sign in</button>
  )
}

export default function Root() {
  return (
    <AuthProvider domain="https://auth.example.com" clientId="your_client_id">
      <App />
    </AuthProvider>
  )
}
```

**Go (server-side middleware)**
```go
import hellojohn "github.com/HelloJohn-OSS/SDKs/go"

client, _ := hellojohn.New(hellojohn.Config{
    Domain: "https://auth.example.com",
    Tenant: "your-tenant",
})

http.Handle("/api/protected", client.RequireAuth(yourHandler))
```

**Node.js (Express)**
```ts
import { HelloJohnVerifier } from "@hellojohn/node"

const verifier = new HelloJohnVerifier({
  domain: "https://auth.example.com",
  tenant: "your-tenant",
})

app.get("/api/data", verifier.requireAuth(), (req, res) => {
  res.json({ user: req.auth.sub })
})
```

**Python (FastAPI)**
```python
from hellojohn import HelloJohnVerifier, require_auth, TokenClaims

verifier = HelloJohnVerifier(domain="https://auth.example.com", tenant="acme")

@app.get("/data")
def data(claims: TokenClaims = Depends(require_auth(verifier))):
    return {"user": claims.sub}
```

See [`SDKs/examples/`](https://github.com/HelloJohn-OSS/SDKs/tree/main/examples) for complete end-to-end examples per platform.

---

## Project Structure

```
hellojohn/
├── cmd/service/main.go              # Entry point
├── internal/
│   ├── app/app.go                   # Dependency wiring
│   ├── http/
│   │   ├── server/config.go         # ← ONLY place that reads env vars
│   │   ├── server/wiring.go         # Service/controller initialization
│   │   ├── controllers/             # HTTP handlers (per domain)
│   │   ├── services/                # Business logic (per domain)
│   │   ├── middlewares/             # Auth, rate limit, CORS, CSRF
│   │   ├── router/                  # Route registration
│   │   └── dto/                     # Request/response types
│   ├── store/                       # Data Access Layer (DAL)
│   │   ├── adapters/fs/             # FileSystem adapter (Control Plane)
│   │   ├── adapters/pg/             # PostgreSQL adapter
│   │   └── adapters/mysql/          # MySQL adapter
│   ├── controlplane/                # Tenant/client/scope management
│   ├── jwt/                         # EdDSA key management, token issuance
│   ├── security/                    # Argon2, TOTP, encryption
│   ├── email/                       # System SMTP service
│   ├── domain/repository/           # Repository interfaces
│   └── cache/                       # Cache abstraction
├── migrations/
│   ├── postgres/tenant/             # PostgreSQL tenant schema migrations
│   └── mysql/tenant/                # MySQL tenant schema migrations
│   # SDKs live in https://github.com/HelloJohn-OSS/SDKs
├── data/hellojohn/                  # Default Control Plane FS root
│   └── tenants/{slug}/
│       ├── tenant.yaml
│       ├── clients.yaml
│       └── scopes.yaml
└── .env.example                     # All environment variables with documentation
```

---

## Tenant Configuration (`tenant.yaml`)

Per-tenant configuration lives in `{FS_ROOT}/tenants/{slug}/tenant.yaml`. The admin API manages this file — you rarely need to edit it manually.

```yaml
id: "550e8400-e29b-41d4-a716-446655440000"
slug: "acme"
name: "ACME Corp"

settings:
  user_db:
    driver: "postgres"           # postgres | mysql
    dsn_enc: "<encrypted DSN>"   # Set via admin API, stored encrypted

  smtp:
    host: "smtp.sendgrid.net"
    port: 587
    from: "noreply@acme.com"
    password_enc: "<encrypted>"

  cache:
    driver: "redis"
    host: "localhost"
    port: 6379

  social_providers:
    - google
    - github

  password_policy:
    min_length: 8
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    breach_detection: true

  bot_protection:
    enabled: true
    site_key: "0x..."            # Overrides global TURNSTILE_SITE_KEY
    secret_key_enc: "<encrypted>"
    protect_login: true
    protect_registration: true
```

---

## npm / npx installer (`hellojohn-oss`)

The `hellojohn-oss` npm package is the recommended way to install and run HelloJohn locally. It is a zero-dependency runtime downloader: it fetches the pre-compiled `hellojohn` and `hjctl` binaries from GitHub Releases and places them in `~/.hellojohn/bin`.

### One-command quickstart

```bash
npx hellojohn-oss quickstart
```

This chains setup → `hjctl local init` → `hjctl local start` automatically.

### Standard flow

```bash
# Download and install binaries
npx hellojohn-oss

# Initialize config (auto-generates cryptographic keys)
hjctl local init

# Start the server
hjctl local start
```

### Other commands

| Command | Description |
|---------|-------------|
| `npx hellojohn-oss` / `npx hellojohn-oss setup` | Download and install binaries |
| `npx hellojohn-oss quickstart` | One-command onboarding |
| `npx hellojohn-oss doctor` | Validate installation |
| `npx hellojohn-oss update` | Re-download latest binaries |
| `npx hellojohn-oss uninstall` | Remove binaries |
| `npx hellojohn-oss hjctl <args>` | Proxy to `hjctl` (useful before PATH is active) |

### Install locations

| Path | Contents |
|------|----------|
| `~/.hellojohn/bin/` | `hellojohn` and `hjctl` binaries |
| `~/.hellojohn/env/default.env` | Default config profile |
| `~/.hellojohn/run/` | PID files, state, and logs |

For the full reference — flags, air-gapped installs, CI usage, troubleshooting — see [`hellojohn-npm-installer`](https://github.com/HelloJohn-OSS/hellojohn-npm-installer#readme).

---

## Running Locally with hjctl

`hjctl local` manages a local HelloJohn instance as a set of background processes.
It handles keys, configuration profiles, health checks, log streaming, and an
optional cloud relay tunnel — all without Docker or a process manager.

```bash
# Build the CLI
go build -o hjctl ./cmd/hjctl

# 1. Initialise a profile (generates SIGNING_MASTER_KEY and SECRETBOX_MASTER_KEY)
hjctl local init

# 2. Start the server in the background
hjctl local start

# 3. Check status
hjctl local status

# 4. (Optional) Connect to the cloud relay tunnel
hjctl local env set HELLOJOHN_CLOUD_URL=https://cloud.hellojohn.com
hjctl local env set HELLOJOHN_TUNNEL_TOKEN=hjtun_...
hjctl local connect

# 5. Stop everything when done
hjctl local stop
```

For the full `hjctl local` reference — including profiles, env management, tunnel
lifecycle, and all flags — see [`cmd/hjctl/README.md`](cmd/hjctl/README.md#local).

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Follow the patterns in [CONTRIBUTING.md](.github/CONTRIBUTING.md) (architecture, naming, DAL usage)
4. Run `go vet ./...` and `go test ./...`
5. Open a pull request

### Development Conventions

- **Controllers** — HTTP-only (parse request, write response). No business logic.
- **Services** — Pure business logic. No `http.ResponseWriter`, no `*http.Request`.
- **DAL** — Always access data via `tda.Users()`, `tda.Tokens()`, etc. Never raw SQL in services.
- **Config** — No `os.Getenv()` outside `server/config.go`. Pass config via Deps structs.
- **Files** — Edit existing files rather than creating new ones when possible.

---

## License

AGPL-3.0 — see [LICENSE](LICENSE).

---

> **HelloJohn** — Built with ❤️ by developers, for developers.
