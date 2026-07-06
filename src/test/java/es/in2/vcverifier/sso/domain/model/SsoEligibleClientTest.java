package es.in2.vcverifier.sso.domain.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * EC-04: normalización trim en punto único de construcción (SsoEligibleClient.of).
 * Sin transformación de caja — el client_id se preserva tal como lo registra el IdP.
 * Rechazo de entradas vacías / nulas / en blanco.
 */
class SsoEligibleClientTest {

    // ─── Normalización trim ───────────────────────────────────────────────────

    @Test
    void of_shouldTrimLeadingAndTrailingWhitespace() {
        SsoEligibleClient client = SsoEligibleClient.of("  my-client  ");

        assertEquals("my-client", client.clientId());
    }

    @Test
    void of_shouldTrimOnlyWhitespace_notInternalSpaces() {
        SsoEligibleClient client = SsoEligibleClient.of("  my client  ");

        assertEquals("my client", client.clientId());
    }

    // ─── Sin transformación de caja ───────────────────────────────────────────

    @Test
    void of_shouldPreserveUpperCasing() {
        SsoEligibleClient client = SsoEligibleClient.of("MY-CLIENT");

        assertEquals("MY-CLIENT", client.clientId());
    }

    @Test
    void of_shouldPreserveMixedCasing() {
        SsoEligibleClient client = SsoEligibleClient.of("MyClient-v2");

        assertEquals("MyClient-v2", client.clientId());
    }

    // ─── Rechazo de entradas inválidas ───────────────────────────────────────

    @Test
    void of_shouldThrowIllegalArgumentException_whenClientIdIsNull() {
        assertThrows(IllegalArgumentException.class,
                () -> SsoEligibleClient.of(null));
    }

    @Test
    void of_shouldThrowIllegalArgumentException_whenClientIdIsEmpty() {
        assertThrows(IllegalArgumentException.class,
                () -> SsoEligibleClient.of(""));
    }

    @Test
    void of_shouldThrowIllegalArgumentException_whenClientIdIsOnlyWhitespace() {
        assertThrows(IllegalArgumentException.class,
                () -> SsoEligibleClient.of("   "));
    }

    // ─── equals / hashCode / toString ────────────────────────────────────────

    @Test
    void equals_shouldReturnTrue_forIdenticalClientIds() {
        SsoEligibleClient a = SsoEligibleClient.of("client-a");
        SsoEligibleClient b = SsoEligibleClient.of("client-a");

        assertEquals(a, b);
        assertEquals(b, a);
    }

    @Test
    void equals_shouldReturnTrue_whenClientIdsDifferOnlyByTrimmedWhitespace() {
        // Ambas instancias resultan en el mismo clientId tras normalización
        SsoEligibleClient a = SsoEligibleClient.of("client-a");
        SsoEligibleClient b = SsoEligibleClient.of("  client-a  ");

        assertEquals(a, b);
    }

    @Test
    void equals_shouldReturnFalse_forDifferentClientIds() {
        SsoEligibleClient a = SsoEligibleClient.of("client-a");
        SsoEligibleClient b = SsoEligibleClient.of("client-b");

        assertNotEquals(a, b);
    }

    @Test
    void hashCode_shouldBeConsistentWithEquals() {
        SsoEligibleClient a = SsoEligibleClient.of("client-a");
        SsoEligibleClient b = SsoEligibleClient.of("client-a");

        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void toString_shouldContainClientIdValue() {
        SsoEligibleClient client = SsoEligibleClient.of("client-a");

        // El record genera SsoEligibleClient[clientId=client-a]; basta con que contenga el valor
        assertTrue(client.toString().contains("client-a"));
    }
}
