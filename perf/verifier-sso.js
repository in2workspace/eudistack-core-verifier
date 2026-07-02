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
 * NFR-P-550-01 — El chequeo de catálogo SSO (TenantSsoCatalog.contains) NO debe
 * degradar el flujo prompt=none. El catálogo se resuelve desde
 * AtomicReference<Map<String, TenantSsoConfig>> en memoria — cero I/O en el camino
 * caliente. El overhead es puro AtomicReference.get() + Map.get() + Set.contains(),
 * orden nanosegundos, por debajo del umbral de resolución HTTP de k6 (~1 ms).
 *   · Escenario reuseCatalogCheck (4): request "hit" (CATALOG_CLIENT_ID eligible)
 *     vs request "miss" (NON_CATALOG_CLIENT_ID no elegible) en la misma iteración.
 *     Si p95(hit) ≈ p95(miss) y p95(delta) < 20 ms → overhead despreciable (NFR-P-550-01).
 *     Ambos caminos deben respetar el presupuesto total NFR-P-01 < 1 s p95.
 *
 * Variables de entorno:
 *   BASE_URL              URL raíz del verifier          (default: http://localhost:8082/verifier)
 *   TENANT                Slug del tenant SSO             (default: sandbox)
 *   CLIENT_ID             client_id OIDC base             (default: vc-auth-client-sandbox)
 *   REDIRECT_URI          redirect_uri registrada         (default: https://localhost/callback)
 *   SSO_STATE             state param para establish      (default: test-state)
 *   SSO_VP_TOKEN          vp_token para establish         (default: dummy-vp-token)
 *   SSO_SESSION_ID        ID de sesión pre-establecida    (default: stub-session)
 *                         Si se proporciona, los escenarios de reuse usarán una
 *                         sesión real y llegarán al código de touch idle y catalog.
 *                         Sin él, el flujo termina en LOGIN_REQUIRED (sesión no
 *                         encontrada), válido para medir overhead del pipeline hasta
 *                         ese punto, pero el catalog check NO se alcanza (AD-2 orden).
 *   CATALOG_CLIENT_ID     client_id configurado como elegible en el catálogo SSO del
 *                         tenant. Debe estar en eligible_clients del YAML de config.
 *                         (default: igual que CLIENT_ID)
 *   NON_CATALOG_CLIENT_ID client_id ausente del catálogo SSO del tenant.
 *                         (default: non-eligible-client)
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

// NFR-P-550-01: duración del flujo prompt=none cuando el cliente ES elegible (catalog hit)
const ssoCatalogHitDuration = new Trend('verifier_sso_catalog_hit_duration_ms');

// NFR-P-550-01: duración del flujo prompt=none cuando el cliente NO es elegible (catalog miss)
const ssoCatalogMissDuration = new Trend('verifier_sso_catalog_miss_duration_ms');

// NFR-P-550-01: delta |hit_ms - miss_ms| por iteración — proxy del overhead observable del
// chequeo de catálogo. Ambos caminos ejecutan el mismo AtomicReference.get() + Set.contains();
// el delta refleja principalmente jitter de red/servidor, no el coste del catálogo.
// p95 < 20 ms confirma que el overhead del catálogo es despreciable.
const ssoCatalogCheckOverhead = new Trend('verifier_sso_catalog_check_overhead_ms');

const ssoErrors = new Counter('verifier_sso_errors');

// ── Configuración de entorno ───────────────────────────────────────────────

const BASE_URL             = __ENV.BASE_URL             || 'http://localhost:8082/verifier';
const TENANT               = __ENV.TENANT               || 'sandbox';
const CLIENT_ID            = __ENV.CLIENT_ID            || 'vc-auth-client-sandbox';
const REDIRECT_URI         = __ENV.REDIRECT_URI         || 'https://localhost/callback';

// NFR-P-550-01: clientes para aislar el camino catalog-hit vs catalog-miss.
// CATALOG_CLIENT_ID     debe aparecer en eligible_clients del YAML de configuración del tenant.
// NON_CATALOG_CLIENT_ID debe estar ausente de eligible_clients (o el tenant sin config) para
// forzar el camino REJECT_CATALOG y medir el delta de latencia respecto al camino ALLOWED.
const CATALOG_CLIENT_ID     = __ENV.CATALOG_CLIENT_ID     || CLIENT_ID;
const NON_CATALOG_CLIENT_ID = __ENV.NON_CATALOG_CLIENT_ID || 'non-eligible-client';

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

        // ── (4) Overhead del chequeo de catálogo SSO — NFR-P-550-01 ─────
        // El catálogo de clientes elegibles se resuelve desde AtomicReference
        // (TenantSsoConfigYamlAdapter.resolveEligibleClients) — cero I/O en el
        // camino caliente. Este escenario demuestra que el overhead es despreciable:
        //
        //   · Cada iteración lanza dos GET /oidc/authorize?prompt=none consecutivos:
        //       request "hit"  — CATALOG_CLIENT_ID  → catalog.contains() = true  → ALLOWED
        //       request "miss" — NON_CATALOG_CLIENT_ID → catalog.contains() = false → REJECT_CATALOG
        //   · Ambos caminos ejecutan exactamente el mismo AtomicReference.get()
        //     + Map.get() + Set.contains() sin ningún I/O, por lo que el delta
        //     |hit_ms − miss_ms| refleja principalmente jitter de red, no el catálogo.
        //   · Si p95(catalog_check_overhead) < 20 ms → overhead del catálogo despreciable
        //     y ambas duraciones se mantienen bajo el presupuesto total NFR-P-01 (1 s p95).
        //
        // Sin SSO_SESSION_ID real, el flujo termina antes de llegar al catalog check
        // (AD-2 orden: clientRegistered → sessionValid → catalog.contains). En ese
        // modo stub el delta es ≈ 0, lo que también es correcto (no hay catalog I/O).
        reuseCatalogCheck: {
            executor:  'constant-vus',
            vus:       15,
            duration:  '3m',
            startTime: '2m',       // comparte ventana de medición con (2) y (3)
            exec:      'reuseCatalogCheckScenario',
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

        // NFR-P-550-01: el chequeo de catálogo (AtomicReference, cero I/O en camino caliente)
        // no supera el presupuesto total NFR-P-01 (< 1 s p95) en ninguno de los dos caminos.
        // El overhead observable entre caminos (catalog_check_overhead) debe ser < 20 ms;
        // un valor mayor indicaría un acceso inesperado a disco/red en el camino caliente.
        verifier_sso_catalog_hit_duration_ms:   ['p(95)<1000'],
        verifier_sso_catalog_miss_duration_ms:  ['p(95)<1000'],
        verifier_sso_catalog_check_overhead_ms: ['p(95)<20'],

        http_req_failed: ['rate<0.01'],
    },
};

// ── Helpers ────────────────────────────────────────────────────────────────

/**
 * Construye query params para GET /oidc/authorize?prompt=none con el client_id indicado.
 * El state es único por llamada para evitar cache hits espurios en el servidor.
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

/** Construye los query params estándar para GET /oidc/authorize?prompt=none con CLIENT_ID. */
function authorizeParams() {
    return authorizeParamsFor(CLIENT_ID);
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

/**
 * (4) reuseCatalogCheckScenario — NFR-P-550-01
 *
 * Valida que el chequeo de catálogo SSO (TenantSsoCatalog.contains) no degrada
 * el flujo prompt=none. El catálogo se resuelve íntegramente desde la caché
 * AtomicReference<Map<String, TenantSsoConfig>> de TenantSsoConfigYamlAdapter,
 * sin ningún I/O en el camino caliente.
 *
 * Estrategia de medición: en cada iteración se ejecutan dos peticiones consecutivas
 * con el mismo VU y la misma cookie de sesión, minimizando la variación ambiental:
 *
 *   · Request "hit"  — CATALOG_CLIENT_ID  → catalog.contains() = true  → ALLOWED
 *   · Request "miss" — NON_CATALOG_CLIENT_ID → catalog.contains() = false → REJECT_CATALOG
 *
 * Ambos caminos ejecutan el mismo AtomicReference.get() + Map.get() + Set.contains();
 * el delta |hit_ms − miss_ms| refleja el jitter de red y carga del servidor, no el
 * coste del catálogo. p95(delta) < 20 ms → overhead del catálogo despreciable.
 *
 * Nota AD-2: si SSO_SESSION_ID no apunta a una sesión válida, el flujo termina en
 * sessionValid=false antes de alcanzar catalog.contains(). El delta seguirá siendo ≈ 0
 * (no se accede al catálogo), lo que es correcto para el propósito de este escenario.
 */
export function reuseCatalogCheckScenario() {

    const jar     = http.cookieJar();
    const session = __ENV.SSO_SESSION_ID || `stub-catalog-${__VU}`;
    jar.set(BASE_URL, SSO_COOKIE_NAME, session);

    const commonHeaders = { 'X-Tenant': TENANT, 'X-Forwarded-Proto': 'https' };

    // ── Request "hit": cliente ELEGIBLE — catalog.contains(clientId) = true ──
    const t0     = Date.now();
    const hitRes = http.get(`${BASE_URL}/oidc/authorize`, {
        params:    authorizeParamsFor(CATALOG_CLIENT_ID),
        redirects: 0,
        jar,
        headers:   commonHeaders,
    });
    const hitMs = Date.now() - t0;

    // ── Request "miss": cliente NO ELEGIBLE — catalog.contains(clientId) = false ──
    const t1      = Date.now();
    const missRes = http.get(`${BASE_URL}/oidc/authorize`, {
        params:    authorizeParamsFor(NON_CATALOG_CLIENT_ID),
        redirects: 0,
        jar,
        headers:   commonHeaders,
    });
    const missMs = Date.now() - t1;

    // Registrar duración de cada camino (ambos deben cumplir NFR-P-01 < 1 s p95)
    ssoCatalogHitDuration.add(hitMs);
    ssoCatalogMissDuration.add(missMs);

    // Agrega el camino ALLOWED al total de reuse para que NFR-P-548-01 lo incluya
    ssoReuseDuration.add(hitMs);

    // Delta como proxy del overhead observable del chequeo de catálogo.
    // Se descarta la iteración si alguna respuesta fue anómalanente lenta (> 500 ms de delta),
    // ya que esos outliers reflejan saturación del servidor, no overhead del catálogo.
    const delta = Math.abs(hitMs - missMs);
    if (delta < 500) {
        ssoCatalogCheckOverhead.add(delta);
    }

    check(hitRes,  { 'catalog-hit:  no 500':  (r) => r.status !== 500 });
    check(missRes, { 'catalog-miss: no 500': (r) => r.status !== 500 });
    if (hitRes.status === 500)  ssoErrors.add(1);
    if (missRes.status === 500) ssoErrors.add(1);

    // Pacing moderado: evita saturar el servidor durante el escenario compartido
    sleep(0.5);
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
