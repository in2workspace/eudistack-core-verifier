package es.in2.vcverifier.sso.domain.model;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AC-03 fail-closed: catálogo vacío → contains siempre false.
 * EC-04: normalización (trim) aplicada a través de SsoEligibleClient.of.
 * Idempotencia: duplicados en la colección de entrada se descartan silenciosamente.
 */
class TenantSsoCatalogTest {

    private static final SsoEligibleClient CLIENT_A = SsoEligibleClient.of("client-a");
    private static final SsoEligibleClient CLIENT_B = SsoEligibleClient.of("client-b");

    // ─── AC-03: catálogo vacío → fail-closed ─────────────────────────────────

    @Test
    void empty_contains_shouldReturnFalse_forAnyClientId() {
        TenantSsoCatalog catalog = TenantSsoCatalog.empty();

        assertFalse(catalog.contains("client-a"));
    }

    @Test
    void of_emptyCollection_contains_shouldReturnFalse() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of());

        assertFalse(catalog.contains("client-a"));
    }

    // ─── contains: presencia y ausencia ──────────────────────────────────────

    @Test
    void contains_shouldReturnTrue_whenClientIsInCatalog() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of(CLIENT_A, CLIENT_B));

        assertTrue(catalog.contains("client-a"));
        assertTrue(catalog.contains("client-b"));
    }

    @Test
    void contains_shouldReturnFalse_whenClientIsNotInCatalog() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of(CLIENT_A));

        assertFalse(catalog.contains("client-b"));
    }

    // ─── AC-03: entradas inválidas → false, sin excepción ────────────────────

    @Test
    void contains_shouldReturnFalse_whenClientIdIsNull() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of(CLIENT_A));

        assertFalse(catalog.contains(null));
    }

    @Test
    void contains_shouldReturnFalse_whenClientIdIsBlank() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of(CLIENT_A));

        assertFalse(catalog.contains("   "));
    }

    // ─── EC-04: normalización trim en contains ────────────────────────────────

    @Test
    void contains_shouldMatchAfterTrim_whenClientIdHasWhitespace() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of(CLIENT_A));

        // SsoEligibleClient.of("  client-a  ") trimea a "client-a" → igualdad con CLIENT_A
        assertTrue(catalog.contains("  client-a  "));
    }

    // ─── Idempotencia: duplicados descartados ─────────────────────────────────

    @Test
    void of_shouldDeduplicateClients_whenSameClientAddedMultipleTimes() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of(CLIENT_A, CLIENT_A, CLIENT_A));

        assertEquals(1, catalog.size());
        assertTrue(catalog.contains("client-a"));
    }

    // ─── isEmpty / size ───────────────────────────────────────────────────────

    @Test
    void isEmpty_shouldReturnTrue_forEmptyCatalog() {
        assertTrue(TenantSsoCatalog.empty().isEmpty());
    }

    @Test
    void isEmpty_shouldReturnFalse_whenCatalogHasClients() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of(CLIENT_A));

        assertFalse(catalog.isEmpty());
    }

    @Test
    void size_shouldReflectNumberOfUniqueClients() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of(CLIENT_A, CLIENT_B));

        assertEquals(2, catalog.size());
    }

    // ─── Guardas de construcción ──────────────────────────────────────────────

    @Test
    void of_shouldThrowNullPointerException_whenCollectionIsNull() {
        assertThrows(NullPointerException.class,
                () -> TenantSsoCatalog.of(null));
    }

    // ─── equals / hashCode ────────────────────────────────────────────────────

    @Test
    void equals_shouldReturnTrue_forCatalogsWithSameClients() {
        TenantSsoCatalog a = TenantSsoCatalog.of(List.of(CLIENT_A));
        TenantSsoCatalog b = TenantSsoCatalog.of(List.of(CLIENT_A));

        assertEquals(a, b);
    }

    @Test
    void equals_shouldReturnFalse_forCatalogsWithDifferentClients() {
        TenantSsoCatalog a = TenantSsoCatalog.of(List.of(CLIENT_A));
        TenantSsoCatalog b = TenantSsoCatalog.of(List.of(CLIENT_B));

        assertNotEquals(a, b);
    }
}
