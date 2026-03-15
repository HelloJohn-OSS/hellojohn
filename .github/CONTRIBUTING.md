# Contributing to HelloJohn OSS

Thanks for your interest in contributing. This document covers everything you need to get started.

## Before you start

- Search [existing issues](https://github.com/HelloJohn-OSS/hellojohn/issues) before opening a new one.
- For significant changes (new features, API changes, architectural decisions), open an issue first to discuss the approach.
- Small bug fixes and documentation improvements can go directly as a PR.

## Development setup

**Requirements:** Go 1.21+, PostgreSQL (for tenant DB tests), Git.

```bash
git clone https://github.com/HelloJohn-OSS/hellojohn.git
cd hellojohn

# Build both binaries
go build -o bin/hellojohn ./cmd/service
go build -o bin/hjctl ./cmd/hjctl

# Run tests
go test ./...
go vet ./...
```

## Project structure

```
cmd/
  service/    # hellojohn server binary
  hjctl/      # CLI binary
  tools/      # internal dev tools
internal/
  bootstrap/  # server startup, config, seeding
  http/       # handlers, services, controllers, DTOs, middleware
  store/      # storage layer (control plane + tenant DBs)
  billing/    # cloud billing (excluded from OSS builds)
  mcp/        # MCP server
migrations/   # SQL migration files
```

## Code conventions

- Follow standard Go conventions (`gofmt`, `go vet` clean).
- Error messages: lowercase, no trailing period.
- Don't add comments unless the logic is non-obvious.
- New HTTP endpoints go in `internal/http/server/` (handler wiring) and `internal/http/services/` (business logic).
- Avoid adding dependencies without discussion — the dependency footprint is intentionally small.

## Submitting a pull request

1. Fork the repo and create a branch from `main`.
2. Make your changes. Add tests for new behavior.
3. Run `go test ./...` and `go vet ./...` — both must pass.
4. Open a PR with a clear description of what and why.
5. Link the related issue if one exists.

## What we accept

- Bug fixes with a clear reproduction case
- Performance improvements with benchmarks
- New OAuth2/OIDC compliance fixes
- Documentation corrections
- Test coverage for existing untested paths

## What belongs in Cloud, not OSS

The following are intentionally **not** part of OSS and PRs adding them will be closed:

- Billing / subscription management
- Managed tunnel relay server
- Cloud control plane (instance registry, proxy)
- HelloJohn Cloud admin UI

## License

By contributing, you agree that your contributions will be licensed under the [AGPL-3.0 License](../LICENSE).
