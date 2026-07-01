import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

/**
 * NFR-P-547-01  verifier_sso_establish_overhead_ms  p95 < 100 ms
 * NFR-P-548-01  verifier_sso_reuse_duration_ms       p95 < 1000 ms
 * NFR-P-549-01  verifier_sso_reuse_touch_active_ms   p95 < 1000 ms
 *               verifier_sso_reuse_touch_throttled_ms p95 < 1000 ms
 *
 * R-1 §3.7.2 — El UPDATE de last_used_at NO debe afectar la latencia p95 del
 * flujo de reutilización SSO (prompt=none). El throttle de 1 update/min
 * (THROTTLE_INTERVAL en ReuseSsoSessionWorkflowImpl) mitiga el riesgo:
 *   · Escenario reuseThrottled   → solicitudes rápidas: touch suprimido por throttle.
 *   · Escenario idleTouchOverhead → 1 req / 70 s: throttle siempre abierto,
 *     CompletableFuture.runAsync(updateLastUsedAt) se dispara en cada request.
 * Si p95(touch_active) ≈ p95(throttled) se verifica que el async dispatch
 * (fire-and-forget) no añade overhead medible al camino de respuesta.
 *
 * Variables de entorno:
 *   BASE_URL          URL raíz del verifier          (default: http://localhost:8082/verifier)
 *   TENANT            Slug del tenant SSO             (default: sandbox)
 *   CLIENT_ID         client_id OIDC                  (default: vc-auth-client-sandbox)
 *   REDIRECT_URI      redirect_uri registrada         (default: https://localhost/callback)
 *   SSO_STATE         state param para establish      (default: test-state)
 *   SSO_VP_TOKEN      vp_token para establish         (default: dummy-vp-token)
 *   SSO_SESSION_ID    ID de sesión pre-establecida    (default: stub-session)
 *                     Si se proporciona, los escenarios de reuse usarán una
 *                     sesión real y llegarán al código de touch idle.
 *                     Sin él, el flujo termina en LOGIN_REQUIRED (sesión no
 *                     encontrada), que sigue siendo válido para medir el
 *                     overhead del pipeline hasta ese punto.
 */

// ── Métricas ───────────────────────────────────────────────────────────────

// NFR-P-547-01: overhead de establecimiento SSO vs baseline OID4VP
const ssoOverhead = new Trend('verifier_sso_establish_overhead_ms');

// NFR-P-548-01: duración total del flujo de reuse (agrega ambos caminos)
const ssoReuseDuration = new Trend('verifier_sso_reuse_duration_ms');

// NFR-P-549-01: camino touch THROTTLED (solicitudes rápidas, <1 min entre sí)
const ssoTouchThrottled = new Trend('verifier_sso_reuse_touch_throttled_ms');

// NFR-P-549-01: camino touch ACTIVO (>1 min entre solicitudes, throttle abierto)
const ssoTouchActive = new Trend('verifier_sso_reuse_touch_active_ms');

const ssoErrors = new Counter('verifier_sso_errors');

// ── Configuración de entorno ───────────────────────────────────────────────

const BASE_URL     = __ENV.BASE_URL     || 'http://localhost:8082/verifier';
const TENANT       = __ENV.TENANT       || 'sandbox';
const CLIENT_ID    = __ENV.CLIENT_ID    || 'vc-auth-client-sandbox';
const REDIRECT_URI = __ENV.REDIRECT_URI || 'https://localhost/callback';

// Nombre de la cookie SSO: espejo de SsoSessionAuthenticationSuccessHandler
const SSO_COOKIE_NAME = `__Secure-sso-${TENANT}`;

// ── Escenarios ─────────────────────────────────────────────────────────────

export const options = {
    scenarios: {

        // ── (1) Overhead de establecimiento SSO ─────────────────────────
        // NFR-P-547-01: mide el delta de latencia entre el flujo OID4VP puro
        // y el flujo SSO completo (POST /oid4vp/auth-response + set-cookie).
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

        // ── (2) Reuse con touch THROTTLED ────────────────────────────────
        // NFR-P-549-01 baseline: 20 VUs enviando GET /oidc/authorize?prompt=none
        // con pacing de 0.5 s → las solicitudes llegan con <<1 min entre ellas.
        // Después del primer toque por sesión, THROTTLE_INTERVAL (60 s) suprime
        // los UPDATE de last_used_at: el flujo no ejecuta el async dispatch.
        // Mide la latencia sin I/O de touch → sirve de baseline para comparar
        // contra el escenario (3).
        reuseThrottled: {
            executor: 'constant-vus',
            vus: 20,
            duration: '2m',
            startTime: '2m',       // arranca tras el calentamiento de establish
            exec: 'reuseThrottledScenario',
        },

        // ── (3) Reuse con touch ACTIVO ───────────────────────────────────
        // NFR-P-549-01 overhead medido: el executor constant-arrival-rate lanza
        // 1 solicitud global cada 70 s. Como 70 s > THROTTLE_INTERVAL (60 s),
        // la condición del throttle (now − lastUsedAt ≥ 1 min) se cumple en
        // cada request → ReuseSsoSessionWorkflowImpl ejecuta:
        //     CompletableFuture.runAsync(() -> sessionRepository.updateLastUsedAt(...))
        // El dispatch es fire-and-forget: la respuesta HTTP no espera al UPDATE.
        // p95(touch_active) debe ser estadísticamente igual a p95(throttled);
        // una diferencia significativa indicaría contención en el ForkJoinPool
        // o un bug que bloquea el camino de respuesta.
        idleTouchOverhead: {
            executor: 'constant-arrival-rate',
            rate: 1,
            timeUnit: '70s',       // >THROTTLE_INTERVAL → touch siempre activo
            duration: '7m',
            preAllocatedVUs: 3,
            maxVUs: 5,
            startTime: '2m',       // comparte ventana de medición con (2)
            exec: 'reuseWithTouchScenario',
        },
    },

    thresholds: {
        // NFR-P-547-01
        verifier_sso_establish_overhead_ms: ['p(95)<100'],

        // NFR-P-548-01: latencia del flujo de reuse (agregado de ambos caminos)
        verifier_sso_reuse_duration_ms: ['p(95)<1000'],

        // NFR-P-549-01 (R-1 §3.7.2):
        // Ambos caminos deben cumplir el mismo umbral. Si p95(touch_active)
        // ≈ p95(throttled) el overhead del async touch es despreciable.
        verifier_sso_reuse_touch_throttled_ms: ['p(95)<1000'],
        verifier_sso_reuse_touch_active_ms:    ['p(95)<1000'],

        http_req_failed: ['rate<0.01'],
    },
};

// ── Helpers ────────────────────────────────────────────────────────────────

/** Construye los query params estándar para GET /oidc/authorize?prompt=none */
function authorizeParams() {
    return {
        client_id:     CLIENT_ID,
        scope:         'openid',
        // state único por solicitud para evitar cache hits espurios en el servidor
        state:         Math.random().toString(36).slice(2, 10),
        redirect_uri:  REDIRECT_URI,
        response_type: 'code',
        prompt:        'none',
    };
}

/** Registra error funcional si el status no es un redirect válido o 200. */
function checkReuse(res, label) {
    const ok = res.status === 302 || res.status === 303 || res.status === 200;
    check(res, { [`${label}: 2xx/3xx`]: () => ok });
    if (!ok) ssoErrors.add(1);
}

/** Registra error funcional para el flujo de establish. */
function checkEstablish(res) {
    const ok = res.status === 200 || res.status === 302 || res.status === 303;
    check(res, {
        'establish: 2xx/3xx':  () => ok,
        'establish: Set-Cookie': (r) => r.headers['Set-Cookie'] !== undefined,
    });
    if (!ok) ssoErrors.add(1);
}

// ── Funciones de escenario exportadas ─────────────────────────────────────

/**
 * (1) measureEstablishOverhead — NFR-P-547-01
 *
 * Delta = latencia(SSO establish) − latencia(baseline OID4VP).
 * Ambas llamadas usan el mismo endpoint POST /oid4vp/auth-response;
 * la diferencia refleja el coste del establish de sesión SSO.
 */
export function measureEstablishOverhead() {

    // Baseline: POST /auth-response sin sesión SSO activa (stub token)
    const t0   = Date.now();
    const base = http.post(`${BASE_URL}/oid4vp/auth-response`, null, {
        headers:   { 'Content-Type': 'application/x-www-form-urlencoded' },
        params:    { state: 'baseline-state', vp_token: 'dummy-vp-token' },
        redirects: 0,
    });
    const baseMs = Date.now() - t0;

    // Flujo SSO: POST /auth-response con estado OIDC real (o stub configurado)
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

    // Solo registrar el overhead si el delta es positivo (evita ruido de medición)
    const overhead = ssoMs - baseMs;
    if (overhead >= 0) ssoOverhead.add(overhead);

    checkEstablish(sso);

    sleep(0.2);
}

/**
 * (2) reuseThrottledScenario — NFR-P-549-01 baseline (touch suprimido)
 *
 * GET /oidc/authorize?prompt=none con la cookie SSO del jar del VU.
 * El pacing (sleep 0.5 s) mantiene las solicitudes por debajo de THROTTLE_INTERVAL,
 * por lo que después de la primera solicitud el throttle suprime los UPDATE.
 * La métrica verifier_sso_reuse_touch_throttled_ms captura la latencia sin
 * overhead de I/O de touch.
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

    // Pacing <<1 min: garantiza que el throttle SIEMPRE esté activo para las
    // solicitudes posteriores a la primera (last_used_at actualizado hace <60 s)
    sleep(0.5);
}

/**
 * (3) reuseWithTouchScenario — NFR-P-549-01 overhead medido (touch activo)
 *
 * El executor constant-arrival-rate (rate=1/70 s) garantiza que entre dos
 * solicitudes del mismo VU siempre hayan pasado >THROTTLE_INTERVAL (60 s).
 * Esto fuerza que ReuseSsoSessionWorkflowImpl evalúe:
 *     Duration.between(session.getLastUsedAt(), now) >= THROTTLE_INTERVAL → true
 * y ejecute:
 *     CompletableFuture.runAsync(() -> sessionRepository.updateLastUsedAt(...))
 * La respuesta HTTP no espera al UPDATE (fire-and-forget); este escenario
 * mide que el dispatch async no añade latencia observable al p95.
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

    // Sin sleep adicional: el pacing de 70 s lo controla el executor
    // constant-arrival-rate (no interferir con el cómputo de arrival rate)
}

// ── Compatibilidad con ejecución directa ───────────────────────────────────

/**
 * Función por defecto para ejecución sin --scenario (k6 run perf/verifier-sso.js).
 * Ejecuta el pipeline completo: baseline → establish → reuse throttled.
 * Para el escenario de touch activo usar: k6 run --scenario idleTouchOverhead ...
 */
export default function () {

    // 1. Baseline OID4VP (sin SSO)
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

    // 3. Reuse SSO (flujo correcto: GET /oidc/authorize?prompt=none)
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
    ssoTouchThrottled.add(reuseMs);   // ejecución directa → sin control de pacing → throttled
    checkReuse(reuse, 'default-reuse');

    sleep(0.2);
}
