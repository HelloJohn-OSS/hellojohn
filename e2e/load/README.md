# Tests de Carga — HelloJohn

Scripts k6 para medir latencia y throughput del sistema bajo carga real.

## Prerequisitos

```bash
# macOS/Linux con Homebrew
brew install k6

# Linux via apt
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6

# Windows via Chocolatey
choco install k6

# Docker (sin instalar k6)
docker run --rm -i grafana/k6 run - < script.js
```

Más info: https://k6.io/docs/get-started/installation/

## Variables de Entorno

| Variable | Default | Descripción |
|---|---|---|
| `TEST_BASE_URL` | `http://localhost:8080` | URL base del servidor HelloJohn |
| `TEST_TENANT_SLUG` | `load-test-tenant` | Tenant para el test de login |
| `TEST_TENANT_COUNT` | `100` | Tenants distintos a simular en MAU test |

## Scripts Disponibles

### `login_load_test.js` — Login concurrente

Simula 100 usuarios virtuales haciendo login simultáneamente durante 30 segundos.

```bash
# Setup
export TEST_BASE_URL=http://localhost:8080
export TEST_TENANT_SLUG=my-tenant

# Correr test
k6 run --vus 100 --duration 30s e2e/load/login_load_test.js

# Docker
docker run --rm -i --network=host \
  -e TEST_BASE_URL=http://localhost:8080 \
  -e TEST_TENANT_SLUG=my-tenant \
  grafana/k6 run - < e2e/load/login_load_test.js
```

### `mau_load_test.js` — MAU tracking multi-tenant

Simula 50 usuarios virtuales accediendo a 100 tenants distintos durante 60 segundos.
Mide la latencia del servidor bajo carga de muchos tenants activos (GDP: global DB pressure).

```bash
# Correr test
k6 run --vus 50 --duration 60s e2e/load/mau_load_test.js

# Con config personalizada
TEST_TENANT_COUNT=500 k6 run --vus 100 --duration 120s e2e/load/mau_load_test.js
```

### `BenchmarkMAUTracking` (Go) — Throughput in-memory

Mide el throughput del Collector de métricas in-memory (no requiere servidor activo).

```bash
go test -bench=BenchmarkMAUTracking -benchtime=10s ./internal/metrics/
go test -bench=. -benchtime=5s ./internal/metrics/
```

## Criterios de Aceptación MVP

| Test | Métrica | Target MVP | Notas |
|---|---|---|---|
| `login_load_test` | p99 latencia | < 500ms | Con pool PG configurado |
| `login_load_test` | Error rate | < 0.1% | HTTP 5xx / total |
| `mau_load_test` | p99 latencia | < 1s | 100 tenants simultáneos |
| `mau_load_test` | Error rate | < 0.1% | |
| `BenchmarkMAUTracking` | Throughput | > 10k ops/s | In-memory, sin DB |
| `BenchmarkCollectorSnapshot` | Throughput | > 100k ops/s | Lectura de snapshot |

> Los targets son orientativos para MVP. Si p99 es levemente superior, documentar
> el resultado real en `EVIDENCE.md` y proceder con el análisis de causa.

## Configuración de Test Recomendada

Para resultados reproducibles, levantar el servidor con una DB de test limpia:

```bash
# 1. DB y servidor
docker-compose -f deployments/docker-compose-storage.yaml up -d
TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/hellojohn_test \
  ./hellojohn serve

# 2. Crear tenant de test
curl -X POST http://localhost:8080/v2/admin/tenants \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"slug":"load-test-tenant","name":"Load Test","db_driver":"postgres","db_dsn":"..."}'

# 3. Correr load tests
k6 run --vus 100 --duration 30s e2e/load/login_load_test.js
```

## Interpretar Resultados

```
✓ http_req_duration.............: avg=45ms  min=12ms med=40ms max=320ms p(90)=85ms p(99)=210ms
✓ http_req_failed...............: 0.00%     ✓ 0 out of 18432

  http_reqs......................: 18432  614.4/s
  iteration_duration.............: avg=163ms min=120ms med=157ms max=495ms p(90)=200ms p(99)=350ms
  vus............................: 100
```

- `p(99)` — El 99% de los requests terminó en X ms
- `http_req_failed` — Porcentaje de requests con error (4xx+5xx)
- `http_reqs/s` — Throughput del servidor (requests por segundo)
