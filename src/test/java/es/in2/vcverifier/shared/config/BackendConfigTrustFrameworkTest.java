package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.BackendProperties;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The DOME trust framework is required by the trusted-issuer and client-registry lookups. */
class BackendConfigTrustFrameworkTest {

    private static BackendConfig configWith(List<BackendProperties.TrustFramework> trustFrameworks) {
        return new BackendConfig(new BackendProperties("http://localhost", null, null, trustFrameworks,
                null, null, null, null, null, null));
    }

    @Test
    void trustedIssuerListUri_domeConfigured_returnsItsUrl() {
        BackendConfig config = configWith(List.of(
                new BackendProperties.TrustFramework("dome", "https://issuers.example/", "https://services.example/")));

        assertEquals("https://issuers.example/", config.getTrustedIssuerListUri());
        assertEquals("https://services.example/", config.getClientsRepositoryUri());
    }

    @Test
    void trustedIssuerListUri_noTrustFrameworks_failsWithExplicitMessage() {
        BackendConfig config = configWith(null);

        IllegalStateException ex = assertThrows(IllegalStateException.class, config::getTrustedIssuerListUri);

        assertTrue(ex.getMessage().contains("DOME"));
    }

    @Test
    void clientsRepositoryUri_emptyTrustFrameworks_failsWithExplicitMessage() {
        BackendConfig config = configWith(List.of());

        assertThrows(IllegalStateException.class, config::getClientsRepositoryUri);
    }

    @Test
    void clientsRepositoryUri_onlyOtherFramework_failsWithExplicitMessage() {
        BackendConfig config = configWith(List.of(
                new BackendProperties.TrustFramework("EBSI", "https://ebsi.example/", "https://ebsi.example/s")));

        assertThrows(IllegalStateException.class, config::getClientsRepositoryUri);
    }
}
