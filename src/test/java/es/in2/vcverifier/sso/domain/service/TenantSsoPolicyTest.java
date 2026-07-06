package es.in2.vcverifier.sso.domain.service;

import es.in2.vcverifier.sso.domain.model.ReuseDecision;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.service.TenantSsoPolicy;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests del overload AD-2 de TenantSsoPolicy.evaluate(6 params).
 *
 * AC-01  ALLOWED cuando las tres condiciones AND se cumplen.
 * AC-02  REJECT_CATALOG cuando el cliente no figura en el catálogo SSO (interaction_required).
 * AC-03  REJECT_CATALOG cuando el catálogo está vacío — fail-closed.
 * AC-05  REJECT_SESSION cuando el cliente no está registrado en el servidor OAuth (login_required).
 * EC-01  REJECT_SESSION cuando la sesión ha expirado, aunque el cliente esté en catálogo (login_required).
 * EC-03  CROSS_TENANT cuando el tenant de la sesión y el de la solicitud difieren.
 * NFR-S-550-01  NullPointerException al pasar catálogo null — el contrato no admite null.
 */
class TenantSsoPolicyTest {

    // Clock fijado en 2026-01-01T10:00:00Z; TTL absoluto de 5 minutos (300 s)
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");
    private static final Clock  CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final long   TTL_SECONDS = 300L;

    private final TenantSsoPolicy policy = new TenantSsoPolicy(CLOCK, TTL_SECONDS);

    // Sesión establecida 1 min antes de NOW → dentro del TTL de 5 min
    private static final Instant SESSION_VALID     = NOW.minusSeconds(60);
    // Sesión establecida 6 min antes de NOW → TTL de 5 min superado
    private static final Instant SESSION_EXPIRED   = NOW.minusSeconds(360);

    private static final TenantSsoCatalog CATALOG_WITH_A =
            TenantSsoCatalog.of(List.of(SsoEligibleClient.of("client-a")));
    private static final TenantSsoCatalog CATALOG_EMPTY  = TenantSsoCatalog.empty();

    // ─── AC-01: caso feliz ────────────────────────────────────────────────────

    @Test
    void evaluate_shouldReturnALLOWED_whenAllThreeConditionsPass() {
        ReuseDecision result = policy.evaluate(
                "tenant-a", "tenant-a",
                SESSION_VALID,
                true,
                CATALOG_WITH_A,
                "client-a"
        );

        assertEquals(ReuseDecision.ALLOWED, result);
    }

    // ─── AC-02: cliente no está en catálogo → interaction_required ────────────

    @Test
    void evaluate_shouldReturnREJECT_CATALOG_whenClientNotInCatalog() {
        ReuseDecision result = policy.evaluate(
                "tenant-a", "tenant-a",
                SESSION_VALID,
                true,
                CATALOG_WITH_A,
                "client-b"   // no figura en el catálogo
        );

        assertEquals(ReuseDecision.REJECT_CATALOG, result);
    }

    // ─── AC-03: catálogo vacío → fail-closed siempre REJECT_CATALOG ──────────

    @Test
    void evaluate_shouldReturnREJECT_CATALOG_whenCatalogIsEmpty() {
        ReuseDecision result = policy.evaluate(
                "tenant-a", "tenant-a",
                SESSION_VALID,
                true,
                CATALOG_EMPTY,
                "client-a"
        );

        assertEquals(ReuseDecision.REJECT_CATALOG, result);
    }

    // ─── AC-05: cliente no registrado en OAuth server → login_required ──────────
    // [W1]: la política devuelve REJECT_UNREGISTERED_CLIENT (distinto de REJECT_SESSION)
    // para distinguir "cliente desconocido" de "sesión inexistente/expirada".

    @Test
    void evaluate_shouldReturnREJECT_UNREGISTERED_CLIENT_whenClientNotRegistered() {
        ReuseDecision result = policy.evaluate(
                "tenant-a", "tenant-a",
                SESSION_VALID,
                false,          // condición (1) falla
                CATALOG_WITH_A,
                "client-a"
        );

        assertEquals(ReuseDecision.REJECT_UNREGISTERED_CLIENT, result);
    }

    // ─── EC-01: sesión expirada → login_required, aunque el cliente esté en catálogo ──

    @Test
    void evaluate_shouldReturnREJECT_SESSION_whenSessionExpired_evenIfClientInCatalog() {
        ReuseDecision result = policy.evaluate(
                "tenant-a", "tenant-a",
                SESSION_EXPIRED,    // condición (2) falla: TTL superado
                true,
                CATALOG_WITH_A,
                "client-a"
        );

        assertEquals(ReuseDecision.REJECT_SESSION, result);
    }

    @Test
    void evaluate_shouldReturnREJECT_SESSION_whenSessionIsNull() {
        ReuseDecision result = policy.evaluate(
                "tenant-a", "tenant-a",
                null,               // condición (2) falla: sesión inexistente
                true,
                CATALOG_WITH_A,
                "client-a"
        );

        assertEquals(ReuseDecision.REJECT_SESSION, result);
    }

    // ─── EC-03: tenant legacy — tenant de sesión distinto al de la solicitud ──

    @Test
    void evaluate_shouldReturnCROSS_TENANT_whenTenantsAreNotEqual() {
        ReuseDecision result = policy.evaluate(
                "tenant-a", "tenant-b",  // tenants distintos
                SESSION_VALID,
                true,
                CATALOG_WITH_A,
                "client-a"
        );

        assertEquals(ReuseDecision.CROSS_TENANT, result);
    }

    // ─── Orden AD-2: condición (1) evaluada antes que condición (3) ──────────

    @Test
    void evaluate_shouldReturnREJECT_UNREGISTERED_CLIENT_notREJECT_CATALOG_whenClientNotRegisteredAndNotInCatalog() {
        // AD-2: la condición (1) clientRegistered se evalúa antes que (3) catalog.contains
        ReuseDecision result = policy.evaluate(
                "tenant-a", "tenant-a",
                SESSION_VALID,
                false,          // condición (1) falla
                CATALOG_EMPTY,  // condición (3) también fallaría
                "client-a"
        );

        assertEquals(ReuseDecision.REJECT_UNREGISTERED_CLIENT, result);
    }

    // ─── NFR-S-550-01: catalog null → excepción explícita ────────────────────

    @Test
    void evaluate_shouldThrowNullPointerException_whenCatalogIsNull() {
        assertThrows(NullPointerException.class, () ->
                policy.evaluate(
                        "tenant-a", "tenant-a",
                        SESSION_VALID,
                        true,
                        null,
                        "client-a"
                )
        );
    }
}
