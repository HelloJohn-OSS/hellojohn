# Makefile — HelloJohn build targets
# Convenciones: usa `tabs` (no spaces) como indentación en las recetas.

.PHONY: build test lint vet test-e2e-multinode

# ─── Build ───────────────────────────────────────────────────────────────────

build:
	go build -o bin/hellojohn ./cmd/service

# ─── Unit Tests ──────────────────────────────────────────────────────────────

test:
	go test ./... -count=1

vet:
	go vet ./...

# ─── E2E Tests — Multi-Node (requieren Docker) ───────────────────────────────
#
# Uso:
#   make test-e2e-multinode
#
# Pre-condiciones:
#   - Docker Engine corriendo localmente
#   - Variables de entorno para keys de CI (o uses los valores de test hardcodeados en docker-compose)
#
# El target:
#   1. Levanta el entorno docker-compose (db + node_a + node_b)
#   2. Espera que los servicios estén healthy (--wait)
#   3. Corre los tests con build tag e2e
#   4. Limpia el entorno docker (down -v) sea cual sea el resultado

test-e2e-multinode:
	@echo "==> Starting multi-node E2E environment..."
	docker compose -f e2e/multi-node/docker-compose.yml up -d --wait
	@echo "==> Running E2E tests (tags: e2e)..."
	go test -v -tags e2e ./e2e/multi-node/... -timeout 120s; \
	EXIT_CODE=$$?; \
	echo "==> Tearing down E2E environment..."; \
	docker compose -f e2e/multi-node/docker-compose.yml down -v; \
	exit $$EXIT_CODE
