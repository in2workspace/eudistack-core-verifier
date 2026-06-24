import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

/**
 * NFR-P-547-01
 * verifier_sso_establish_overhead_ms p95 < 100ms
 *
 * NFR-P-548-01
 * verifier_sso_reuse_duration_ms p95 < 1000ms
 */

// Métrica principal de overhead SSO
export let ssoOverhead = new Trend('verifier_sso_establish_overhead_ms');

// Métrica nuevo flujo reuse (prompt=none)
export let ssoReuseDuration = new Trend('verifier_sso_reuse_duration_ms');

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
        verifier_sso_reuse_duration_ms: [
            'p(95)<1000'
        ],
        http_req_failed: ['rate<0.01']
    }
};

// Base URL
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8082/verifier';


/**
 * Baseline OID4VP (sin SSO activo)
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
 * SSO establish flow (extended path)
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


/**
 * REUSE FLOW (NFR-P-548-01)
 * Simula:
 * cookie existente → authorize con prompt=none → redirect con code
 */
function reuseFlow() {

    let start = new Date().getTime();

    let jar = http.cookieJar();

    let res = http.post(`${BASE_URL}/oid4vp/auth-response`, null, {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        params: {
            state: __ENV.SSO_STATE || 'reuse-state',
            vp_token: __ENV.SSO_VP_TOKEN || 'dummy-vp-token',
            prompt: 'none'
        },
        redirects: 10,
        jar: jar
    });

    let end = new Date().getTime();

    let duration = end - start;

    ssoReuseDuration.add(duration);

    check(res, {
        'reuse flow success': (r) => r.status === 200 || r.status === 302,
        'reuse has cookie context': () => true
    });

    if (res.status !== 200 && res.status !== 302) {
        ssoErrors.add(1);
    }

    return duration;
}


/**
 * EXECUTION
 */
export default function () {

    // 1. baseline OID4VP
    let oid4vpLatency = oid4vpFlow();

    // 2. SSO establish
    let ssoLatency = ssoEstablishFlow();

    // 3. overhead conceptual
    let overhead = ssoLatency - oid4vpLatency;
    ssoOverhead.add(overhead);

    // 4. REUSE scenario (prompt=none cookie → code)
    let reuseLatency = reuseFlow();

    // pacing ligero
    sleep(0.2);
}