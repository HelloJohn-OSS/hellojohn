// k6 load test: 100 logins concurrentes
// Uso: k6 run --vus 100 --duration 30s e2e/load/login_load_test.js
//
// Variables de entorno:
//   TEST_BASE_URL    — URL base del servidor (default: http://localhost:8080)
//   TEST_TENANT_SLUG — Slug del tenant de test (default: load-test-tenant)
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const errorRate = new Rate('errors');
const loginDuration = new Trend('login_duration', true);

export const options = {
    vus: 100,
    duration: '30s',
    thresholds: {
        http_req_duration: ['p(99)<500'],   // p99 < 500ms
        http_req_failed: ['rate<0.001'],     // error rate < 0.1%
        errors: ['rate<0.001'],
    },
};

const BASE_URL = __ENV.TEST_BASE_URL || 'http://localhost:8080';
const TENANT_SLUG = __ENV.TEST_TENANT_SLUG || 'load-test-tenant';

export default function () {
    const start = Date.now();

    const payload = JSON.stringify({
        email: `user-${__VU}@loadtest.example.com`,
        password: 'TestPassword123!',
    });

    const params = {
        headers: { 'Content-Type': 'application/json' },
        timeout: '10s',
    };

    // Intentar login via password flow
    const loginURL = `${BASE_URL}/t/${TENANT_SLUG}/v2/auth/login`;
    const res = http.post(loginURL, payload, params);

    const duration = Date.now() - start;
    loginDuration.add(duration);

    const ok = check(res, {
        'status is not 5xx': (r) => r.status < 500,
        'response has body': (r) => r.body && r.body.length > 0,
    });

    errorRate.add(!ok);

    sleep(0.1);
}

export function handleSummary(data) {
    const p99 = data.metrics.http_req_duration?.values?.['p(99)'] || 0;
    const errRate = data.metrics.http_req_failed?.values?.rate || 0;

    console.log(`\n=== RESUMEN LOGIN LOAD TEST ===`);
    console.log(`p99 latencia: ${p99.toFixed(2)}ms (target: <500ms) ${p99 < 500 ? '✓' : '✗'}`);
    console.log(`Error rate:   ${(errRate * 100).toFixed(3)}% (target: <0.1%) ${errRate < 0.001 ? '✓' : '✗'}`);
    console.log(`VUs: ${data.metrics.vus_max?.values?.max || 100}, Duration: 30s`);

    return {
        stdout: JSON.stringify(data, null, 2),
    };
}
