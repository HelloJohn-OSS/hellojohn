// k6 load test: MAU tracking bajo carga con múltiples tenants
// Uso: k6 run --vus 50 --duration 60s e2e/load/mau_load_test.js
//
// Variables de entorno:
//   TEST_BASE_URL      — URL base del servidor (default: http://localhost:8080)
//   TEST_TENANT_COUNT  — Número de tenants distintos a simular (default: 100)
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Counter } from 'k6/metrics';

const errorRate = new Rate('errors');
const tenantRequests = new Counter('tenant_requests');

export const options = {
    vus: 50,
    duration: '60s',
    thresholds: {
        http_req_duration: ['p(99)<1000'],  // p99 < 1s
        http_req_failed: ['rate<0.001'],     // error rate < 0.1%
        errors: ['rate<0.001'],
    },
};

const BASE_URL = __ENV.TEST_BASE_URL || 'http://localhost:8080';
const TENANT_COUNT = parseInt(__ENV.TEST_TENANT_COUNT || '100', 10);

export default function () {
    // Simular múltiples tenants activos simultáneamente
    const tenantIdx = Math.floor(Math.random() * TENANT_COUNT);
    const tenantSlug = `load-tenant-${tenantIdx}`;

    // OIDC discovery endpoint — ligero, existe en todos los tenants
    const oidcURL = `${BASE_URL}/t/${tenantSlug}/.well-known/openid-configuration`;
    const res = http.get(oidcURL, { timeout: '5s' });

    tenantRequests.add(1);

    const ok = check(res, {
        'not 5xx': (r) => r.status < 500,
        'has body': (r) => r.body && r.body.length > 0,
    });

    errorRate.add(!ok);
}

export function handleSummary(data) {
    const p99 = data.metrics.http_req_duration?.values?.['p(99)'] || 0;
    const errRate = data.metrics.http_req_failed?.values?.rate || 0;
    const totalReqs = data.metrics.http_reqs?.values?.count || 0;

    console.log(`\n=== RESUMEN MAU LOAD TEST ===`);
    console.log(`p99 latencia:     ${p99.toFixed(2)}ms (target: <1000ms) ${p99 < 1000 ? '✓' : '✗'}`);
    console.log(`Error rate:       ${(errRate * 100).toFixed(3)}% (target: <0.1%) ${errRate < 0.001 ? '✓' : '✗'}`);
    console.log(`Total requests:   ${totalReqs}`);
    console.log(`Tenants únicos:   ${TENANT_COUNT} (simulados)`);

    return {
        stdout: JSON.stringify(data, null, 2),
    };
}
