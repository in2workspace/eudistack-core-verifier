import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

/**
 * NFR-P-547-01
 * verifier_sso_establish_overhead_ms p95 < 100ms
 */

// Métrica principal de overhead SSO
export let ssoOverhead = new Trend('verifier_sso_establish_overhead_ms');

// Errores funcionales
export let ssoErrors = new Counter('verifier_sso_errors');

// Configuración de carga
export let options = {
    stages: [
        { duration: '30s', target: 20 },
        { duration: '1m', target: 50 },
        { duration: '30s', target: 0 }
    ],
    thresholds: {
        verifier_sso_establish_overhead_ms: [
            'p(95)<100'
        ],
        http_req_failed: ['rate<0.01']
    }
};

// Puerto 8082 y context path /verifier según configuración de la app
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8082/verifier';

/**
 * Simulación baseline OID4VP
 * Endpoint real: POST /oid4vp/auth-response
 */
function oid4vpFlow() {
    let res = http.post(`${BASE_URL}/oid4vp/auth-response`, null, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        params: {
            state: 'dummy-state',
            vp_token: 'dummy-vp-token'
        }
    });

    return res.timings.duration;
}

/**
 * Flow con SSO (verifier extended path)
 * El endpoint SSO se establece a través de /oid4vp/auth-response con credenciales válidas.
 */
function ssoEstablishFlow() {

    let start = new Date().getTime();

    let res = http.post(`${BASE_URL}/oid4vp/auth-response`, null, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        params: {
            state: __ENV.SSO_STATE || 'test-state',
            vp_token: __ENV.SSO_VP_TOKEN || 'dummy-vp-token'
        }
    });

    let end = new Date().getTime();

    let duration = end - start;

    ssoOverhead.add(duration);

    check(res, {
        'SSO establish success': (r) => r.status === 200 || r.status === 302,
        'has Set-Cookie': (r) => r.headers['Set-Cookie'] !== undefined
    });

    if (res.status !== 200 && res.status !== 302) {
        ssoErrors.add(1);
    }

    return duration;
}

export default function () {

    // 1. baseline (OID4VP sin sesión SSO activa)
    let oid4vpLatency = oid4vpFlow();

    // 2. SSO extended path
    let ssoLatency = ssoEstablishFlow();

    // 3. overhead conceptual (SSO - baseline)
    let overhead = ssoLatency - oid4vpLatency;

    ssoOverhead.add(overhead);

    // pacing ligero
    sleep(0.2);
}