import http from 'k6/http';
import { check } from 'k6';
import { Trend, Counter } from 'k6/metrics';

/**
 * NFR-S-554-01 — POST /tenant/sso/revoke  p95 < 2 s with up to 1000 live sessions per tenant.
 *
 * Run: k6 run -e TENANT=sandbox -e ADMIN_BEARER=$TOKEN perf/tenant-sso-revoke.js
 */

const revokeDuration = new Trend('tenant_sso_revoke_ms');
const revokeErrors   = new Counter('tenant_sso_revoke_errors');

const BASE_URL     = __ENV.BASE_URL     || 'http://localhost:8082/verifier';
const TENANT       = __ENV.TENANT       || 'sandbox';
const SEED_COUNT   = parseInt(__ENV.SEED_COUNT || '1000', 10);
const ADMIN_BEARER = __ENV.ADMIN_BEARER || '';
const ADMIN_COOKIE = __ENV.ADMIN_COOKIE || '';
const RESEED_URL   = __ENV.RESEED_URL   || '';

const ITERATIONS = RESEED_URL ? parseInt(__ENV.ITERATIONS || '1', 10) : 1;

const REVOKE_URL = `${BASE_URL}/tenant/sso/revoke`;

export const options = {
    scenarios: {
        emergencyRevoke: {
            executor: 'shared-iterations',
            vus: 1,
            iterations: ITERATIONS,
            maxDuration: '5m',
            exec: 'revokeScenario',
        },
    },
    thresholds: {
        tenant_sso_revoke_ms: ['p(95)<2000'],
        http_req_failed:      ['rate<0.01'],
    },
};

function adminHeaders() {
    const headers = {
        'X-Tenant': TENANT,
        'X-Forwarded-Proto': 'https',
        'X-Correlation-Id': `perf-554-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    };
    if (ADMIN_BEARER) headers['Authorization'] = `Bearer ${ADMIN_BEARER}`;
    if (ADMIN_COOKIE) headers['Cookie'] = ADMIN_COOKIE;
    return headers;
}

function reseedIfConfigured() {
    if (!RESEED_URL) return;
    const res = http.post(RESEED_URL, JSON.stringify({ tenant: TENANT, count: SEED_COUNT }), {
        headers: { 'Content-Type': 'application/json', ...adminHeaders() },
    });
    check(res, { 'reseed: 2xx': (r) => r.status >= 200 && r.status < 300 });
}

export function setup() {
    console.log(`[NFR-S-554-01] Target ${REVOKE_URL} tenant=${TENANT} expected seeded=${SEED_COUNT}`);
    console.log('[NFR-S-554-01] PRECONDITION: 1000 rows seeded for the tenant (see header SQL).');
    console.log('[NFR-S-554-01] PRECONDITION: DELETE plan must use a tenant-leading index (EXPLAIN, see header).');
    if (!RESEED_URL) {
        console.log('[NFR-S-554-01] RESEED_URL not set → single-iteration mode (first revoke only is meaningful).');
    }
    if (!ADMIN_BEARER && !ADMIN_COOKIE) {
        console.warn('[NFR-S-554-01] No ADMIN_BEARER/ADMIN_COOKIE set → expect 401/403 from the admin filter chain.');
    }
}

export function revokeScenario() {
    reseedIfConfigured();

    const t0  = Date.now();
    const res = http.post(REVOKE_URL, null, { headers: adminHeaders() });
    const ms  = Date.now() - t0;

    revokeDuration.add(ms);

    const ok = check(res, {
        'revoke: 200 OK': (r) => r.status === 200,
        'revoke: count_revoked present': (r) => {
            try { return typeof r.json('count_revoked') === 'number'; } catch (_) { return false; }
        },
        'revoke: revoked the seeded volume': (r) => {
            if (!RESEED_URL) return true;
            try { return r.json('count_revoked') >= SEED_COUNT; } catch (_) { return false; }
        },
    });
    if (!ok) revokeErrors.add(1);
}
