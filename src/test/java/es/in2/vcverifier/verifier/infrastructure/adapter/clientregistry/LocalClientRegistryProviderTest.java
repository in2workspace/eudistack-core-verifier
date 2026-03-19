package es.in2.vcverifier.verifier.infrastructure.adapter.clientregistry;

import es.in2.vcverifier.verifier.domain.model.ExternalTrustedListYamlData;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalClientRegistryProviderTest {

    @Test
    void retrieveClients_fromDefaultLocalYaml_success() {
        LocalClientRegistryProvider provider = new LocalClientRegistryProvider();

        ExternalTrustedListYamlData data = provider.retrieveClients();

        assertNotNull(data);
        assertNotNull(data.clients());
        assertFalse(data.clients().isEmpty());
        assertEquals("vc-auth-client", data.clients().get(0).clientId());
    }

    @Test
    void retrieveClients_containsExpectedDevClient() {
        LocalClientRegistryProvider provider = new LocalClientRegistryProvider();

        ExternalTrustedListYamlData data = provider.retrieveClients();

        var client = data.clients().get(0);
        assertEquals("vc-auth-client", client.clientId());
        assertTrue(client.redirectUris().contains("http://localhost:4200"));
        assertTrue(client.scopes().contains("openid"));
        assertTrue(client.scopes().contains("learcredential"));
    }

    @Test
    void retrieveClients_externalPathNotFound_fallsBackToClasspath() {
        LocalClientRegistryProvider provider = new LocalClientRegistryProvider("/nonexistent/path.yaml");

        ExternalTrustedListYamlData data = provider.retrieveClients();

        assertNotNull(data);
        assertFalse(data.clients().isEmpty());
    }
}
