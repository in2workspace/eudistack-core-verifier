import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

/**
 * Suite de performance — SSO Verifier
 *
 * NFR-P-547-01  verifier_sso_establish_overhead_ms  p95 < 100 ms
 * NFR-P-548-01  verifier_sso_reuse_duration_ms      p95 < 1 000 ms
 * NFR-P-549-01  verifier_sso_touch_overhead_ms      p95 < 50 ms
 *               El touch idle (throttle 1 update/min) NO debe añadir latencia
 *               observable al flujo de reutilización prompt=none (R-1 §3.7.2).
 *               El Thread.ofVirtual().start() del servidor es non-blocking;
 *               si p95 supera 50 ms indica saturación del pool JDBC o contención.
 */

// ── Métricas ───────────────────────────────────────────────────────────────

// NFR-P-547-01: overhead de escritura de la sesión en el establish
const ssoEstablishOverheadMs = new Trend('verifier_sso_establish_overhead_ms');

// NFR-P-548-01: latencia total del flujo de reutilización (baseline)
const ssoReuseDurationMs = new Trend('verifier_sso_reuse_duration_ms');

// NFR-P-549-01 — dos carriles del mismo flujo prompt=none según la ventana de throttle:
//   touch    → primer reuse tras >= 1 min sin actividad (Thread.ofVirtual dispara updateLastUsedAt)
//   notouch  → reuses dentro de la ventana de 1 min (update suprimido por el throttle)
const ssoReuseTouchMs   = new Trend('verifier_sso_reuse_touch_ms');
const ssoReuseNoTouchMs = new Trend('verifier_sso_reuse_notouch_ms');

// Delta por-VU: touch_duration − notouch_duration medidos en la misma VU para
// aislar la varianza de red. Alimenta el umbral NFR-P-549-01.
const ssoTouchOverheadMs = new Trend('verifier_sso_touch_overhead_ms');

// Contador de errores funcionales (HTTP no 2xx / 3xx)
const ssoErrors = new Counter('verifier_sso_errors');

// ── Configuración de entorno ───────────────────────────────────────────────

const BASE_URL     = __ENV.BASE_URL     || 'http://localhost:8082';
const TENANT       = __ENV.TENANT       || 'sandbox';
const CLIENT_ID    = __ENV.CLIENT_ID    || 'test-client';
const REDIRECT_URI = __ENV.REDIRECT_URI || 'https://localhost/callback';
const SSO_STATE    = __ENV.SSO_STATE    || 'perf-state';
const SSO_VP_TOKEN = __ENV.SSO_VP_TOKEN || 'dummy-vp-token';

// Debe coincidir con THROTTLE_INTERVAL del servidor (ReuseSsoSessionWorkflowImpl)
const THROTTLE_MS = 60_000;

// Nombre de la cookie SSO (espejado de la convención __Secure-sso-{tenant})
const COOKIE_NAME = `__Secure-sso-${TENANT}`;

// ── Escenarios ─────────────────────────────────────────────────────────────

export const options = {
    scenarios: {

        // ── S1: overhead del establish (NFR-P-547-01) ──────────────────────
        // Mide el tiempo extra que introduce la escritura de sso_session frente
        // al flujo OID4VP puro. El ramp evita una avalancha inicial.
        sso_establish: {
            executor:   'ramping-vus',
            startVUs:   0,
            stages: [
                { duration: '30s', target: 20 },
                { duration: '1m',  target: 50 },
                { duration: '30s', target: 0  },
            ],
            exec:        'establishScenario',
        },

        // ── S2: baseline reuse prompt=none (NFR-P-548-01) ──────────────────
        // Carga sostenida de reutilización a llegada constante. Cada VU tiene
        // lastUsedAt reciente (< 1 min) → throttle suprime el touch → mide
        // la latencia del camino feliz sin efecto del update asíncrono.
        // startTime 0s: corre en paralelo con S1 para reflejar carga mixta real.
        sso_reuse_baseline: {
            executor:        'constant-arrival-rate',
            rate:            20,
            timeUnit:        '1s',
            duration:        '2m',
            preAllocatedVUs: 20,
            maxVUs:          100,
            exec:            'reuseBaselineScenario',
        },

        // ── S3: overhead del idle touch con throttle (NFR-P-549-01) ────────
        // startTime 90s: las sesiones creadas en S1 tienen lastUsedAt >= 90 s
        // atrás, por encima del umbral de 1 min. El primer reuse de cada VU
        // provoca el path "touch" (Thread.ofVirtual dispara updateLastUsedAt).
        //
        // Cada VU ejecuta 1 iteración del ciclo:
        //   1. Un request "touch"   → servidor escribe last_used_at async
        //   2. N requests "notouch" → throttle suprime el update
        //   3. ssoTouchOverheadMs   = touch_duration − media(notouch_durations)
        //
        // Con iterations:1 y 10 VUs se consiguen 10 muestras "touch" limpias.
        // Subir iterations o vus aumenta la densidad sin tocar la lógica.
        sso_idle_touch_overhead: {
            executor:    'per-vu-iterations',
            vus:         10,
            iterations:  1,
            maxDuration: '3m',
            exec:        'idleTouchOverheadScenario',
            startTime:   '90s',
        },
    },

    thresholds: {
        // NFR-P-547-01
        verifier_sso_establish_overhead_ms: ['p(95)<100'],

        // NFR-P-548-01
        verifier_sso_reuse_duration_ms:     ['p(95)<1000'],

        // NFR-P-549-01: ambos caminos dentro del mismo SLA de reutilización
        verifier_sso_reuse_touch_ms:        ['p(95)<1000'],
        verifier_sso_reuse_notouch_ms:      ['p(95)<1000'],

        // NFR-P-549-01: el overhead neto del Thread.ofVirtual debe ser < 50 ms p95
        // Un valor > 50 ms indica contención en el pool JDBC o en el scheduler JVM.
        verifier_sso_touch_overhead_ms:     ['p(95)<50'],

        http_req_failed:                    ['rate<0.01'],
    },
};

// ── Helpers compartidos ────────────────────────────────────────────────────

/**
 * Baseline OID4VP sin SSO: POST /oid4vp/auth-response sin cookie.
 * Se usa para calcular el overhead de establish (delta respecto al flujo puro).
 */
function oid4vpBaselineRequest() {
    return http.post(
        `${BASE_URL}/oid4vp/auth-response`,
        null,
        {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            params:  { state: SSO_STATE, vp_token: SSO_VP_TOKEN },
        }
    );
}

/**
 * Llamada al endpoint de autorización con prompt=none y cookie SSO.
 * Este es el flujo de reutilización real que ejercita ReuseSsoSessionWorkflowImpl.
 *
 * @param {http.CookieJar} jar - jar con la cookie __Secure-sso-{tenant} precargada
 */
function authorizeReuseRequest(jar) {
    return http.get(
        `${BASE_URL}/oidc/authorize`,
        {
            headers: {
                'X-Tenant':          TENANT,
                'X-Forwarded-Proto': 'https',
            },
            params: {
                client_id:     CLIENT_ID,
                scope:         'openid',
                state:         SSO_STATE,
                redirect_uri:  REDIRECT_URI,
                prompt:        'none',
            },
            redirects: 0,   // capturamos el 3xx sin seguirlo para medir sólo la latencia del verifier
            jar:       jar,
        }
    );
}

/**
 * Devuelve true si el status es 2xx o 3xx (ambos son respuestas válidas del authorize).
 */
function isSuccess(status) {
    return status >= 200 && status < 400;
}

// ── S1: establish (NFR-P-547-01) ──────────────────────────────────────────

export function establishScenario() {
    // 1. Baseline OID4VP puro
    let baselineRes = oid4vpBaselineRequest();
    let baselineMs  = baselineRes.timings.duration;

    // 2. Flujo SSO establish: la respuesta incluye Set-Cookie con la sesión
    let start       = Date.now();
    let establishRes = http.post(
        `${BASE_URL}/oid4vp/auth-response`,
        null,
        {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Tenant':     TENANT,
            },
            params: { state: SSO_STATE, vp_token: SSO_VP_TOKEN },
        }
    );
    let establishMs = Date.now() - start;

    // 3. Overhead = tiempo adicional introducido por la escritura de la sesión
    let overhead = Math.max(0, establishMs - baselineMs);
    ssoEstablishOverheadMs.add(overhead);

    check(establishRes, {
        'establish: 2xx/3xx':    (r) => isSuccess(r.status),
        'establish: Set-Cookie': (r) => r.headers['Set-Cookie'] !== undefined,
    });

    if (!isSuccess(establishRes.status)) {
        ssoErrors.add(1);
    }

    sleep(0.2);
}

// ── S2: reuse baseline (NFR-P-548-01) ─────────────────────────────────────

export function reuseBaselineScenario() {
    let jar = http.cookieJar();
    jar.set(BASE_URL, COOKIE_NAME, __ENV.SSO_SESSION_ID || 'perf-session-id');

    let start = Date.now();
    let res   = authorizeReuseRequest(jar);
    let ms    = Date.now() - start;

    ssoReuseDurationMs.add(ms);

    check(res, {
        'reuse baseline: 2xx/3xx': (r) => isSuccess(r.status),
    });

    if (!isSuccess(res.status)) {
        ssoErrors.add(1);
    }

    // Sin sleep: carga sostenida a llegada constante controlada por el executor
}

// ── S3: overhead touch idle (NFR-P-549-01) ────────────────────────────────
//
// Diseño de la medición:
//
//   El throttle del servidor (THROTTLE_INTERVAL = 1 min) suprime el UPDATE
//   de last_used_at si el último touch fue hace < 1 min.
//
//   Cada VU ejecuta el siguiente ciclo una sola vez (iterations:1):
//
//     a) NOTOUCH_BURST: N requests rápidos (< 1 min entre sí).
//        El jar se reutiliza → servidor ve la misma sesión con lastUsedAt fresco.
//        → throttle suprime el update → mide ssoReuseNoTouchMs
//        → almacena la media como baselineMs para el delta
//
//     b) Espera THROTTLE_MS + margen (63 s) → simula inactividad del usuario
//
//     c) TOUCH: 1 request con la misma sesión, lastUsedAt > 1 min atrás.
//        → servidor dispara Thread.ofVirtual().start(updateLastUsedAt) de forma
//          no bloqueante y devuelve la respuesta de autorización.
//        → mide ssoReuseTouchMs
//        → delta = touchMs − baselineMs → ssoTouchOverheadMs
//
//   El delta por-VU aísla la varianza de red ya que ambas mediciones
//   se hacen en la misma VU, con el mismo servidor, en condiciones similares.

const NOTOUCH_BURST_COUNT = 5;   // requests rápidos antes del touch
const TOUCH_WAIT_S        = 63;  // segundos de espera para superar el throttle (1 min + margen)

export function idleTouchOverheadScenario() {
    let jar = http.cookieJar();

    // Usamos un session ID inyectado por entorno o un stub para pruebas de carga sintéticas
    let sessionId = __ENV.SSO_SESSION_ID || 'perf-session-id';
    jar.set(BASE_URL, COOKIE_NAME, sessionId);

    // ── a) NOTOUCH burst: establece el baseline de latencia para esta VU ──
    let noTouchTotal = 0;
    let noTouchCount = 0;

    for (let i = 0; i < NOTOUCH_BURST_COUNT; i++) {
        let start = Date.now();
        let res   = authorizeReuseRequest(jar);
        let ms    = Date.now() - start;

        ssoReuseNoTouchMs.add(ms);
        noTouchTotal += ms;
        noTouchCount++;

        check(res, {
            'notouch burst: 2xx/3xx': (r) => isSuccess(r.status),
        });

        if (!isSuccess(res.status)) {
            ssoErrors.add(1);
        }

        // Pequeño jitter entre requests del burst para no saturar la misma conexión
        sleep(0.05);
    }

    let noTouchMeanMs = noTouchCount > 0 ? noTouchTotal / noTouchCount : 0;

    // ── b) Espera hasta que el throttle del servidor expira ────────────────
    // La sesión lleva TOUCH_WAIT_S sin actividad → lastUsedAt > 1 min atrás
    sleep(TOUCH_WAIT_S);

    // ── c) TOUCH: primer reuse tras la ventana de inactividad ─────────────
    let touchStart = Date.now();
    let touchRes   = authorizeReuseRequest(jar);
    let touchMs    = Date.now() - touchStart;

    ssoReuseTouchMs.add(touchMs);

    // Delta por-VU: overhead neto del Thread.ofVirtual (debe ser < 50 ms p95)
    if (noTouchMeanMs > 0) {
        let overhead = touchMs - noTouchMeanMs;
        ssoTouchOverheadMs.add(overhead);
    }

    check(touchRes, {
        'touch: 2xx/3xx':                     (r) => isSuccess(r.status),
        'touch: latency within SLA (<1000ms)': () => touchMs < 1000,
    });

    if (!isSuccess(touchRes.status)) {
        ssoErrors.add(1);
    }
}
