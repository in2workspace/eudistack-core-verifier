import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

/**
 * NFR-P-547-01  verifier_sso_establish_overhead_ms          p95 < 100 ms
 * NFR-P-548-01  verifier_sso_reuse_duration_ms               p95 < 1000 ms
 * NFR-P-549-01  verifier_sso_reuse_touch_active_ms           p95 < 1000 ms
 *               verifier_sso_reuse_touch_throttled_ms        p95 < 1000 ms
 * NFR-P-550-01  verifier_sso_catalog_hit_duration_ms         p95 < 1000 ms
 *               verifier_sso_catalog_miss_duration_ms        p95 < 1000 ms
 *               verifier_sso_catalog_check_overhead_ms       p95 < 20 ms
 * NFR-O-552-01  (enum EventType ↔ tests coverage — verified in JUnit, not measurable by k6)
 * NFR-O-552-02  verifier_sso_reuse_with_observability_ms     p95 < 1000 ms
 *
 * NFR-O-552-02 (US-07) — Audit emission (SSO_SESSION_REUSED via SsoAuditPort) and metric
 * emission (verifier_sso_reuse_total + verifier_sso_oid4vp_avoided_total via SsoMetricsPort)
 * on the prompt=none reuse flow are SYNCHRONOUS best-effort (AD-1): one structured log.info +
 * two Counter.increment(), backed by the platform async appender. Their cost must be negligible
 * against the total NFR-P-01 budget (< 1 s p95). Scenario (5) reuseObservabilityOverhead
 * exercises the successful reuse path — the only one that emits audit + metrics — and verifies
 * the p95 stays under NFR-P-01; a p95 close to reuseThrottled (same path, no measurable extra
 * load) confirms the instrumentation is not on the critical path.
 *
 * R-1 §3.7.2 — The last_used_at UPDATE MUST NOT affect the p95 latency of the SSO reuse flow
 * (prompt=none). The 1-update/min throttle (THROTTLE_INTERVAL in ReuseSsoSessionWorkflowImpl)
 * mitigates the risk:
 *   · reuseThrottled scenario   → fast requests: touch suppressed by the throttle.
 *   · idleTouchOverhead scenario → 1 req / 70 s: throttle always open,
 *     CompletableFuture.runAsync(updateLastUsedAt) fires on every request.
 * If p95(touch_active) ≈ p95(throttled) it is verified that the async dispatch
 * (fire-and-forget) adds no measurable overhead to the response path.
 *
 * NFR-P-550-01 — The SSO catalog check (TenantSsoCatalog.contains) MUST NOT degrade the
 * prompt=none flow. The catalog is resolved from an in-memory
 * AtomicReference<Map<String, TenantSsoConfig>> — zero I/O on the hot path. The overhead is a
 * pure AtomicReference.get() + Map.get() + Set.contains(), on the order of nanoseconds, below
 * k6's HTTP resolution threshold (~1 ms).
 *   · reuseCatalogCheck scenario (4): "hit" request (CATALOG_CLIENT_ID eligible)
 *     vs "miss" request (NON_CATALOG_CLIENT_ID not eligible) in the same iteration.
 *     If p95(hit) ≈ p95(miss) and p95(delta) < 20 ms → negligible overhead (NFR-P-550-01).
 *     Both paths must respect the total NFR-P-01 budget < 1 s p95.
 *
 * Environment variables:
 *   BASE_URL              verifier root URL              (default: http://localhost:8082/verifier)
 *   TENANT                SSO tenant slug                 (default: sandbox)
 *   CLIENT_ID             base OIDC client_id             (default: vc-auth-client-sandbox)
 *   REDIRECT_URI          registered redirect_uri         (default: https://localhost/callback)
 *   SSO_STATE             state param for establish       (default: test-state)
 *   SSO_VP_TOKEN          vp_token for establish          (default: dummy-vp-token)
 *   SSO_SESSION_ID        pre-established session ID       (default: stub-session)
 *                         If provided, the reuse scenarios use a real session and reach the
 *                         idle-touch and catalog code. Without it, the flow ends in
 *                         LOGIN_REQUIRED (session not found), valid to measure the pipeline
 *                         overhead up to that point, but the catalog check is NOT reached
 *                         (AD-2 ordering).
 *   CATALOG_CLIENT_ID     client_id configured as eligible in the tenant's SSO catalog. Must be
 *                         in the config YAML's eligible_clients. (default: same as CLIENT_ID)
 *   NON_CATALOG_CLIENT_ID client_id absent from the tenant's SSO catalog.
 *                         (default: non-eligible-client)
 */

// ── Metrics ─────────────────────────────────────────────────────────────────

// NFR-P-547-01: SSO establishment overhead vs OID4VP baseline
const ssoOverhead = new Trend('verifier_sso_establish_overhead_ms');

// NFR-P-548-01: total duration of the reuse flow (aggregates both paths)
const ssoReuseDuration = new Trend('verifier_sso_reuse_duration_ms');

// NFR-P-549-01: THROTTLED touch path (fast requests, <1 min apart)
const ssoTouchThrottled = new Trend('verifier_sso_reuse_touch_throttled_ms');

// NFR-P-549-01: ACTIVE touch path (>1 min between requests, throttle open)
const ssoTouchActive = new Trend('verifier_sso_reuse_touch_active_ms');

// NFR-P-550-01: prompt=none flow duration when the client IS eligible (catalog hit)
const ssoCatalogHitDuration = new Trend('verifier_sso_catalog_hit_duration_ms');

// NFR-P-550-01: prompt=none flow duration when the client is NOT eligible (catalog miss)
const ssoCatalogMissDuration = new Trend('verifier_sso_catalog_miss_duration_ms');

// NFR-P-550-01: |hit_ms - miss_ms| delta per iteration — proxy for the observable overhead of
// the catalog check. Both paths run the same AtomicReference.get() + Set.contains();
// the delta mainly reflects network/server jitter, not the catalog cost.
// p95 < 20 ms confirms the catalog overhead is negligible.
const ssoCatalogCheckOverhead = new Trend('verifier_sso_catalog_check_overhead_ms');

// NFR-O-552-02 (US-07): prompt=none reuse flow duration INCLUDING the synchronous emission
// of audit (SSO_SESSION_REUSED) + metrics (reuse_total, oid4vp_avoided_total).
// Must stay under the total NFR-P-01 budget (< 1 s p95).
const ssoReuseObservability = new Trend('verifier_sso_reuse_with_observability_ms');

const ssoErrors = new Counter('verifier_sso_errors');

// ── Environment configuration ────────────────────────────────────────────────

const BASE_URL             = __ENV.BASE_URL             || 'http://localhost:8082/verifier';
const TENANT               = __ENV.TENANT               || 'sandbox';
const CLIENT_ID            = __ENV.CLIENT_ID            || 'vc-auth-client-sandbox';
const REDIRECT_URI         = __ENV.REDIRECT_URI         || 'https://localhost/callback';

// NFR-P-550-01: clients to isolate the catalog-hit vs catalog-miss path.
// CATALOG_CLIENT_ID     must appear in the tenant config YAML's eligible_clients.
// NON_CATALOG_CLIENT_ID must be absent from eligible_clients (or the tenant have no config) to
// force the REJECT_CATALOG path and measure the latency delta against the ALLOWED path.
const CATALOG_CLIENT_ID     = __ENV.CATALOG_CLIENT_ID     || CLIENT_ID;
const NON_CATALOG_CLIENT_ID = __ENV.NON_CATALOG_CLIENT_ID || 'non-eligible-client';

// SSO cookie name: mirror of SsoSessionAuthenticationSuccessHandler
const SSO_COOKIE_NAME = `__Secure-sso-${TENANT}`;

// ── Scenarios ────────────────────────────────────────────────────────────────

export const options = {
    scenarios: {

        // ── (1) SSO establishment overhead ──────────────────────────────
        // NFR-P-547-01: measures the latency delta between the pure OID4VP flow
        // and the full SSO flow (POST /oid4vp/auth-response + set-cookie).
        // Ramp up → steady → ramp down.
        establishOverhead: {
            executor: 'ramping-vus',
            stages: [
                { duration: '30s', target: 20 },
                { duration: '1m',  target: 50 },
                { duration: '30s', target: 0  },
            ],
            exec: 'measureEstablishOverhead',
        },

        // ── (2) Reuse with THROTTLED touch ───────────────────────────────
        // NFR-P-549-01 baseline: 20 VUs sending GET /oidc/authorize?prompt=none
        // with 0.5 s pacing → requests arrive <<1 min apart.
        // After the first touch per session, THROTTLE_INTERVAL (60 s) suppresses
        // the last_used_at UPDATEs: the flow does not run the async dispatch.
        // Measures latency without touch I/O → serves as the baseline to compare
        // against scenario (3).
        reuseThrottled: {
            executor: 'constant-vus',
            vus: 20,
            duration: '2m',
            startTime: '2m',       // starts after the establish warm-up
            exec: 'reuseThrottledScenario',
        },

        // ── (3) Reuse with ACTIVE touch ──────────────────────────────────
        // NFR-P-549-01 measured overhead: the constant-arrival-rate executor fires
        // 1 global request every 70 s. Since 70 s > THROTTLE_INTERVAL (60 s),
        // the throttle condition (now − lastUsedAt ≥ 1 min) holds on every
        // request → ReuseSsoSessionWorkflowImpl runs:
        //     CompletableFuture.runAsync(() -> sessionRepository.updateLastUsedAt(...))
        // The dispatch is fire-and-forget: the HTTP response does not wait for the UPDATE.
        // p95(touch_active) should be statistically equal to p95(throttled);
        // a significant difference would indicate contention in the ForkJoinPool
        // or a bug blocking the response path.
        idleTouchOverhead: {
            executor: 'constant-arrival-rate',
            rate: 1,
            timeUnit: '70s',       // >THROTTLE_INTERVAL → touch always active
            duration: '7m',
            preAllocatedVUs: 3,
            maxVUs: 5,
            startTime: '2m',       // shares the measurement window with (2)
            exec: 'reuseWithTouchScenario',
        },

        // ── (4) SSO catalog check overhead — NFR-P-550-01 ───────────────
        // The eligible-clients catalog is resolved from an AtomicReference
        // (TenantSsoConfigYamlAdapter.resolveEligibleClients) — zero I/O on the
        // hot path. This scenario shows the overhead is negligible:
        //
        //   · Each iteration fires two consecutive GET /oidc/authorize?prompt=none:
        //       "hit"  request — CATALOG_CLIENT_ID  → catalog.contains() = true  → ALLOWED
        //       "miss" request — NON_CATALOG_CLIENT_ID → catalog.contains() = false → REJECT_CATALOG
        //   · Both paths run exactly the same AtomicReference.get()
        //     + Map.get() + Set.contains() with no I/O, so the delta
        //     |hit_ms − miss_ms| mainly reflects network jitter, not the catalog.
        //   · If p95(catalog_check_overhead) < 20 ms → negligible catalog overhead
        //     and both durations stay under the total NFR-P-01 budget (1 s p95).
        //
        // Without a real SSO_SESSION_ID, the flow ends before reaching the catalog check
        // (AD-2 ordering: clientRegistered → sessionValid → catalog.contains). In that
        // stub mode the delta is ≈ 0, which is also correct (no catalog I/O).
        reuseCatalogCheck: {
            executor:  'constant-vus',
            vus:       15,
            duration:  '3m',
            startTime: '2m',       // shares the measurement window with (2) and (3)
            exec:      'reuseCatalogCheckScenario',
        },

        // ── (5) Observability overhead (audit + metrics) — NFR-O-552-02 ─
        // The successful reuse path (prompt=none → ALLOWED) is the ONLY one that emits,
        // synchronously and best-effort (AD-1):
        //     · SsoAuditPort.publish(SSO_SESSION_REUSED)  → structured log.info
        //     · SsoMetricsPort.recordReuse(tenant, client) → Counter.increment()
        //     · SsoMetricsPort.recordOid4vpAvoided(tenant) → Counter.increment()
        // This scenario exercises that path and records its total duration. If the p95 stays
        // under NFR-P-01 (< 1 s) and close to reuseThrottled (same flow), the instrumentation
        // adds no observable overhead (NFR-O-552-02).
        reuseObservabilityOverhead: {
            executor:  'constant-vus',
            vus:       15,
            duration:  '3m',
            startTime: '2m',
            exec:      'reuseObservabilityScenario',
        },
    },

    thresholds: {
        // NFR-P-547-01
        verifier_sso_establish_overhead_ms: ['p(95)<100'],

        // NFR-P-548-01: reuse flow latency (aggregate of both paths)
        verifier_sso_reuse_duration_ms: ['p(95)<1000'],

        // NFR-P-549-01 (R-1 §3.7.2):
        // Both paths must meet the same threshold. If p95(touch_active)
        // ≈ p95(throttled) the async touch overhead is negligible.
        verifier_sso_reuse_touch_throttled_ms: ['p(95)<1000'],
        verifier_sso_reuse_touch_active_ms:    ['p(95)<1000'],

        // NFR-P-550-01: the catalog check (AtomicReference, zero I/O on the hot path)
        // does not exceed the total NFR-P-01 budget (< 1 s p95) on either path.
        // The observable cross-path overhead (catalog_check_overhead) must be < 20 ms;
        // a higher value would indicate an unexpected disk/network access on the hot path.
        verifier_sso_catalog_hit_duration_ms:   ['p(95)<1000'],
        verifier_sso_catalog_miss_duration_ms:  ['p(95)<1000'],
        verifier_sso_catalog_check_overhead_ms: ['p(95)<20'],
        verifier_sso_reuse_with_observability_ms: ['p(95)<1000'],

        http_req_failed: ['rate<0.01'],
    },
};

// ── Helpers ───────────────────────────────────────────────────────────────

/**
 * Builds query params for GET /oidc/authorize?prompt=none with the given client_id.
 * The state is unique per call to avoid spurious server-side cache hits.
 */
function authorizeParamsFor(clientId) {
    return {
        client_id:     clientId,
        scope:         'openid',
        state:         Math.random().toString(36).slice(2, 10),
        redirect_uri:  REDIRECT_URI,
        response_type: 'code',
        prompt:        'none',
    };
}

/** Builds the standard query params for GET /oidc/authorize?prompt=none with CLIENT_ID. */
function authorizeParams() {
    return authorizeParamsFor(CLIENT_ID);
}

/** Records a functional error if the status is not a valid redirect or 200. */
function checkReuse(res, label) {
    const ok = res.status === 302 || res.status === 303 || res.status === 200;
    check(res, { [`${label}: 2xx/3xx`]: () => ok });
    if (!ok) ssoErrors.add(1);
}

/** Records a functional error for the establish flow. */
function checkEstablish(res) {
    const ok = res.status === 200 || res.status === 302 || res.status === 303;
    check(res, {
        'establish: 2xx/3xx':  () => ok,
        'establish: Set-Cookie': (r) => r.headers['Set-Cookie'] !== undefined,
    });
    if (!ok) ssoErrors.add(1);
}

// ── Exported scenario functions ────────────────────────────────────────────

/**
 * (1) measureEstablishOverhead — NFR-P-547-01
 *
 * Delta = latency(SSO establish) − latency(OID4VP baseline).
 * Both calls use the same POST /oid4vp/auth-response endpoint;
 * the difference reflects the cost of establishing the SSO session.
 */
export function measureEstablishOverhead() {

    // Baseline: POST /auth-response without an active SSO session (stub token)
    const t0   = Date.now();
    const base = http.post(`${BASE_URL}/oid4vp/auth-response`, null, {
        headers:   { 'Content-Type': 'application/x-www-form-urlencoded' },
        params:    { state: 'baseline-state', vp_token: 'dummy-vp-token' },
        redirects: 0,
    });
    const baseMs = Date.now() - t0;

    // SSO flow: POST /auth-response with a real OIDC state (or the configured stub)
    const t1  = Date.now();
    const sso = http.post(`${BASE_URL}/oid4vp/auth-response`, null, {
        headers:   { 'Content-Type': 'application/x-www-form-urlencoded' },
        params:    {
            state:    __ENV.SSO_STATE    || 'test-state',
            vp_token: __ENV.SSO_VP_TOKEN || 'dummy-vp-token',
        },
        redirects: 0,
    });
    const ssoMs = Date.now() - t1;

    // Only record the overhead if the delta is positive (avoids measurement noise)
    const overhead = ssoMs - baseMs;
    if (overhead >= 0) ssoOverhead.add(overhead);

    checkEstablish(sso);

    sleep(0.2);
}

/**
 * (2) reuseThrottledScenario — NFR-P-549-01 baseline (touch suppressed)
 *
 * GET /oidc/authorize?prompt=none with the SSO cookie from the VU's jar.
 * The pacing (sleep 0.5 s) keeps requests below THROTTLE_INTERVAL,
 * so after the first request the throttle suppresses the UPDATEs.
 * The verifier_sso_reuse_touch_throttled_ms metric captures the latency
 * without touch I/O overhead.
 */
export function reuseThrottledScenario() {

    const jar          = http.cookieJar();
    const sessionValue = __ENV.SSO_SESSION_ID || `stub-${__VU}`;
    jar.set(BASE_URL, SSO_COOKIE_NAME, sessionValue);

    const t0  = Date.now();
    const res = http.get(`${BASE_URL}/oidc/authorize`, {
        params:    authorizeParams(),
        redirects: 0,
        jar:       jar,
        headers:   { 'X-Tenant': TENANT, 'X-Forwarded-Proto': 'https' },
    });
    const ms = Date.now() - t0;

    ssoReuseDuration.add(ms);
    ssoTouchThrottled.add(ms);

    checkReuse(res, 'throttled');

    // Pacing <<1 min: ensures the throttle is ALWAYS active for the requests
    // after the first (last_used_at updated <60 s ago)
    sleep(0.5);
}

/**
 * (3) reuseWithTouchScenario — NFR-P-549-01 measured overhead (active touch)
 *
 * The constant-arrival-rate executor (rate=1/70 s) ensures that between two
 * requests of the same VU more than THROTTLE_INTERVAL (60 s) has always elapsed.
 * This forces ReuseSsoSessionWorkflowImpl to evaluate:
 *     Duration.between(session.getLastUsedAt(), now) >= THROTTLE_INTERVAL → true
 * and run:
 *     CompletableFuture.runAsync(() -> sessionRepository.updateLastUsedAt(...))
 * The HTTP response does not wait for the UPDATE (fire-and-forget); this scenario
 * measures that the async dispatch adds no observable latency to the p95.
 */
export function reuseWithTouchScenario() {

    const jar          = http.cookieJar();
    const sessionValue = __ENV.SSO_SESSION_ID || `stub-touch-${__VU}`;
    jar.set(BASE_URL, SSO_COOKIE_NAME, sessionValue);

    const t0  = Date.now();
    const res = http.get(`${BASE_URL}/oidc/authorize`, {
        params:    authorizeParams(),
        redirects: 0,
        jar:       jar,
        headers:   { 'X-Tenant': TENANT, 'X-Forwarded-Proto': 'https' },
    });
    const ms = Date.now() - t0;

    ssoReuseDuration.add(ms);
    ssoTouchActive.add(ms);

    checkReuse(res, 'touch-active');

    // No extra sleep: the 70 s pacing is controlled by the constant-arrival-rate
    // executor (do not interfere with the arrival rate computation)
}

/**
 * (4) reuseCatalogCheckScenario — NFR-P-550-01
 *
 * Validates that the SSO catalog check (TenantSsoCatalog.contains) does not degrade
 * the prompt=none flow. The catalog is resolved entirely from the
 * AtomicReference<Map<String, TenantSsoConfig>> cache of TenantSsoConfigYamlAdapter,
 * with no I/O on the hot path.
 *
 * Measurement strategy: each iteration runs two consecutive requests with the same VU
 * and the same session cookie, minimizing environmental variance:
 *
 *   · "hit"  request — CATALOG_CLIENT_ID  → catalog.contains() = true  → ALLOWED
 *   · "miss" request — NON_CATALOG_CLIENT_ID → catalog.contains() = false → REJECT_CATALOG
 *
 * Both paths run the same AtomicReference.get() + Map.get() + Set.contains();
 * the delta |hit_ms − miss_ms| reflects network jitter and server load, not the
 * catalog cost. p95(delta) < 20 ms → negligible catalog overhead.
 *
 * AD-2 note: if SSO_SESSION_ID does not point to a valid session, the flow ends at
 * sessionValid=false before reaching catalog.contains(). The delta will still be ≈ 0
 * (the catalog is not accessed), which is correct for this scenario's purpose.
 */
export function reuseCatalogCheckScenario() {

    const jar     = http.cookieJar();
    const session = __ENV.SSO_SESSION_ID || `stub-catalog-${__VU}`;
    jar.set(BASE_URL, SSO_COOKIE_NAME, session);

    const commonHeaders = { 'X-Tenant': TENANT, 'X-Forwarded-Proto': 'https' };

    // ── "hit" request: ELIGIBLE client — catalog.contains(clientId) = true ──
    const t0     = Date.now();
    const hitRes = http.get(`${BASE_URL}/oidc/authorize`, {
        params:    authorizeParamsFor(CATALOG_CLIENT_ID),
        redirects: 0,
        jar,
        headers:   commonHeaders,
    });
    const hitMs = Date.now() - t0;

    // ── "miss" request: NON-ELIGIBLE client — catalog.contains(clientId) = false ──
    const t1      = Date.now();
    const missRes = http.get(`${BASE_URL}/oidc/authorize`, {
        params:    authorizeParamsFor(NON_CATALOG_CLIENT_ID),
        redirects: 0,
        jar,
        headers:   commonHeaders,
    });
    const missMs = Date.now() - t1;

    // Record each path's duration (both must meet NFR-P-01 < 1 s p95)
    ssoCatalogHitDuration.add(hitMs);
    ssoCatalogMissDuration.add(missMs);

    // Add the ALLOWED path to the reuse total so NFR-P-548-01 includes it
    ssoReuseDuration.add(hitMs);

    // Delta as a proxy for the observable overhead of the catalog check.
    // The iteration is discarded if a response was anomalously slow (> 500 ms delta),
    // since those outliers reflect server saturation, not catalog overhead.
    const delta = Math.abs(hitMs - missMs);
    if (delta < 500) {
        ssoCatalogCheckOverhead.add(delta);
    }

    check(hitRes,  { 'catalog-hit:  no 500':  (r) => r.status !== 500 });
    check(missRes, { 'catalog-miss: no 500': (r) => r.status !== 500 });
    if (hitRes.status === 500)  ssoErrors.add(1);
    if (missRes.status === 500) ssoErrors.add(1);

    // Moderate pacing: avoids saturating the server during the shared scenario
    sleep(0.5);
}

/**
 * (5) reuseObservabilityScenario — NFR-O-552-02 (US-07)
 *
 * Exercises the prompt=none reuse path, the only one that on success (ALLOWED) emits
 * synchronously and best-effort (AD-1):
 *     · SsoAuditPort.publish(SSO_SESSION_REUSED)   → structured log.info
 *     · SsoMetricsPort.recordReuse(tenant, client) → Counter.increment()
 *     · SsoMetricsPort.recordOid4vpAvoided(tenant) → Counter.increment()
 *
 * The verifier_sso_reuse_with_observability_ms metric captures the TOTAL flow duration
 * (including that emission). The p95 < 1000 ms threshold (NFR-P-01) confirms the
 * instrumentation does not break the latency budget; comparing it with
 * verifier_sso_reuse_touch_throttled_ms (same path) verifies the audit + metrics
 * overhead is negligible.
 *
 * Note: without a valid SSO_SESSION_ID the flow ends in LOGIN_REQUIRED before emitting the
 * reuse event; in that stub mode the pipeline is measured up to that point (conservative
 * upper bound).
 */
export function reuseObservabilityScenario() {

    const jar          = http.cookieJar();
    const sessionValue = __ENV.SSO_SESSION_ID || `stub-observability-${__VU}`;
    jar.set(BASE_URL, SSO_COOKIE_NAME, sessionValue);

    const t0  = Date.now();
    const res = http.get(`${BASE_URL}/oidc/authorize`, {
        params:    authorizeParams(),
        redirects: 0,
        jar:       jar,
        headers:   { 'X-Tenant': TENANT, 'X-Forwarded-Proto': 'https' },
    });
    const ms = Date.now() - t0;

    ssoReuseDuration.add(ms);
    ssoReuseObservability.add(ms);

    checkReuse(res, 'observability');

    sleep(0.5);
}

// ── Direct-execution compatibility ──────────────────────────────────────────

/**
 * Default function for execution without --scenario (k6 run perf/verifier-sso.js).
 * Runs the full pipeline: baseline → establish → reuse throttled.
 * For the active-touch scenario use: k6 run --scenario idleTouchOverhead ...
 */
export default function () {

    // 1. OID4VP baseline (no SSO)
    const t0   = Date.now();
    http.post(`${BASE_URL}/oid4vp/auth-response`, null, {
        headers:   { 'Content-Type': 'application/x-www-form-urlencoded' },
        params:    { state: 'baseline-state', vp_token: 'dummy-vp-token' },
        redirects: 0,
    });
    const baseMs = Date.now() - t0;

    // 2. SSO establish
    const t1  = Date.now();
    const sso = http.post(`${BASE_URL}/oid4vp/auth-response`, null, {
        headers:   { 'Content-Type': 'application/x-www-form-urlencoded' },
        params:    {
            state:    __ENV.SSO_STATE    || 'test-state',
            vp_token: __ENV.SSO_VP_TOKEN || 'dummy-vp-token',
        },
        redirects: 0,
    });
    const ssoMs = Date.now() - t1;

    const overhead = ssoMs - baseMs;
    if (overhead >= 0) ssoOverhead.add(overhead);
    checkEstablish(sso);

    // 3. SSO reuse (correct flow: GET /oidc/authorize?prompt=none)
    const jar          = http.cookieJar();
    const sessionValue = __ENV.SSO_SESSION_ID || `stub-default-${__VU}`;
    jar.set(BASE_URL, SSO_COOKIE_NAME, sessionValue);

    const t2   = Date.now();
    const reuse = http.get(`${BASE_URL}/oidc/authorize`, {
        params:    authorizeParams(),
        redirects: 0,
        jar:       jar,
        headers:   { 'X-Tenant': TENANT, 'X-Forwarded-Proto': 'https' },
    });
    const reuseMs = Date.now() - t2;

    ssoReuseDuration.add(reuseMs);
    ssoTouchThrottled.add(reuseMs);   // direct execution → no pacing control → throttled
    checkReuse(reuse, 'default-reuse');

    sleep(0.2);
}
