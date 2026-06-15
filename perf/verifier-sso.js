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

// URLs (ajusta según entorno)
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

/**
 * Simulación baseline OID4VP
 * (sin SSO layer)
 */
function oid4vpFlow() {
    let res = http.post(`${BASE_URL}/oid4vp/verify`, JSON.stringify({
        vp_token: "dummy-vp",
        presentation_submission: {}
    }), {
        headers: { 'Content-Type': 'application/json' }
    });

    return res.timings.duration;
}

/**
 * Flow con SSO (verifier extended path)
 */
function ssoEstablishFlow() {

    let start = new Date().getTime();

    let res = http.post(`${BASE_URL}/sso/establish`, JSON.stringify({
        tenant: "tenant-a",
        holderHash: "holder-xyz",
        clientId: "client-test",
        sub: "user-123"
    }), {
        headers: { 'Content-Type': 'application/json' }
    });

    let end = new Date().getTime();

    let duration = end - start;

    ssoOverhead.add(duration);

    check(res, {
        'SSO establish success': (r) => r.status === 200,
        'has cookie or session': (r) => r.headers['Set-Cookie'] !== undefined
    });

    if (res.status !== 200) {
        ssoErrors.add(1);
    }

    return duration;
}

export default function () {

    // 1. baseline (OID4VP)
    let oid4vpLatency = oid4vpFlow();

    // 2. SSO extended path
    let ssoLatency = ssoEstablishFlow();

    // 3. overhead conceptual (SSO - baseline)
    let overhead = ssoLatency - oid4vpLatency;

    ssoOverhead.add(overhead);

    // pacing ligero
    sleep(0.2);
}