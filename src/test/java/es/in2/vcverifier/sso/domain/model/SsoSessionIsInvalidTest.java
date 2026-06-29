package es.in2.vcverifier.sso.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests unitarios para SsoSession.isValid(Instant now, Duration idleTtl).
 *
 * isValid() evalúa dos condiciones de forma independiente:
 *   1. TTL absoluto: now < expiresAt
 *   2. TTL idle:     (now - lastUsedAt) ≤ idleTtl
 *
 * El parámetro `now` es inyectable, lo que permite controlar el instante
 * evaluado sin necesidad de alterar el reloj del sistema.
 *
 * AC-04: sesión válida — ambas condiciones satisfechas → true
 * AC-05: TTL idle excedido, TTL absoluto OK → false
 * EC-02: TTL absoluto expirado → false (aunque idle fuera válido)
 */
class SsoSessionIsInvalidTest {

    private static final String TENANT      = "tenant-a";
    private static final String HOLDER_HASH = "holder-hash-001";

    // =========================================================
    // AC-04: sesión activa dentro de ambos TTLs → isValid = true
    // =========================================================

    @Test
    void isValid_returnsTrue_whenWithinAbsoluteAndIdleTtl() {
        SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(1));

        Instant establishedAt = session.getEstablishedAt();
        // now = 15 min tras establecimiento; idleTtl = 30 min → ambas condiciones OK
        Instant now = establishedAt.plusSeconds(15 * 60);

        assertThat(session.isValid(now, Duration.ofMinutes(30))).isTrue();
    }

    @Test
    void isValid_returnsTrue_exactlyAtIdleBoundary() {
        SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(1));

        Instant establishedAt = session.getEstablishedAt();
        // now = exactamente en el límite idle (30 min) → ≤ 0 → válido
        Instant now = establishedAt.plusSeconds(30 * 60);

        assertThat(session.isValid(now, Duration.ofMinutes(30))).isTrue();
    }

    // =========================================================
    // AC-05: TTL idle excedido, TTL absoluto aún vigente → isValid = false
    // =========================================================

    @Test
    void isValid_returnsFalse_whenIdleTtlExceeded() {
        SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(1));

        Instant establishedAt = session.getEstablishedAt();
        // now = 31 min tras establecimiento; idleTtl = 30 min → idle excedido
        // expiresAt = establishedAt + 1h → TTL absoluto NO expirado
        Instant now = establishedAt.plusSeconds(31 * 60);

        assertThat(session.isValid(now, Duration.ofMinutes(30))).isFalse();
    }

    @Test
    void isValid_returnsFalse_whenIdleExceededAfterTouch() {
        SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(2));

        Instant touchAt = session.getEstablishedAt().plusSeconds(10 * 60);
        session.touch(touchAt);

        // now = touch + 31 min; idleTtl = 30 min → idle excedido desde el último touch
        Instant now = touchAt.plusSeconds(31 * 60);

        assertThat(session.isValid(now, Duration.ofMinutes(30))).isFalse();
    }

    // =========================================================
    // EC-02: TTL absoluto expirado → isValid = false independiente del idle
    // =========================================================

    @Test
    void isValid_returnsFalse_whenAbsoluteTtlExpired() {
        // TTL mínimo permitido (5 min) para minimizar el offset necesario
        SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, SsoTtlRange.MIN_ABSOLUTE);

        // now = 1 segundo después del vencimiento absoluto
        // idleTtl extremadamente grande para aislar la condición absoluta
        Instant now = session.getExpiresAt().plusSeconds(1);

        assertThat(session.isValid(now, Duration.ofHours(24))).isFalse();
    }

    @Test
    void isValid_returnsFalse_whenAbsoluteTtlExpired_andIdleWouldAlsoBeExceeded() {
        SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, SsoTtlRange.MIN_ABSOLUTE);

        // Ambas condiciones fallidas: now muy en el futuro
        Instant now = session.getExpiresAt().plusSeconds(3600);

        assertThat(session.isValid(now, Duration.ofMinutes(30))).isFalse();
    }

    // =========================================================
    // touch() actualiza lastUsedAt y restablece el idle TTL
    // =========================================================

    @Test
    void isValid_returnsTrue_afterTouchResetsIdleWindow() {
        SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(2));

        // Simular que han pasado 31 min y la sesión sería inválida por idle
        Instant afterIdle = session.getEstablishedAt().plusSeconds(31 * 60);
        assertThat(session.isValid(afterIdle, Duration.ofMinutes(30))).isFalse();

        // Hacer touch en t=31min y re-evaluar 15 min después del touch
        session.touch(afterIdle);
        Instant afterTouch = afterIdle.plusSeconds(15 * 60);
        assertThat(session.isValid(afterTouch, Duration.ofMinutes(30))).isTrue();
    }
}
