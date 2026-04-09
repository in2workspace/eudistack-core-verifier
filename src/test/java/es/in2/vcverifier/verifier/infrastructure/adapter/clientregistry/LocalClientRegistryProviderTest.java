package es.in2.vcverifier.verifier.infrastructure.adapter.clientregistry;

import es.in2.vcverifier.verifier.domain.model.ExternalTrustedListYamlData;
import org.junit.jupiter.api.Test;

import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class LocalClientRegistryProviderTest {

    @Test
    void retrieveClients_fromExternalYaml_success() {
        String path = resolveTestFixture("test-fixtures/clients.yaml");
        LocalClientRegistryProvider provider = new LocalClientRegistryProvider(path);

        ExternalTrustedListYamlData data = provider.retrieveClients();

        assertNotNull(data);
        assertNotNull(data.clients());
        assertFalse(data.clients().isEmpty());
        assertEquals("vc-auth-client-test", data.clients().get(0).clientId());
    }

    @Test
    void retrieveClients_containsExpectedScopes() {
        String path = resolveTestFixture("test-fixtures/clients.yaml");
        LocalClientRegistryProvider provider = new LocalClientRegistryProvider(path);

        ExternalTrustedListYamlData data = provider.retrieveClients();

        var client = data.clients().get(0);
        assertTrue(client.scopes().contains("openid"));
        assertTrue(client.scopes().contains("learcredential"));
    }

    @Test
    void retrieveClients_externalPathNotFound_throwsException() {
        LocalClientRegistryProvider provider = new LocalClientRegistryProvider("/nonexistent/path.yaml");

        assertThrows(IllegalStateException.class, provider::retrieveClients);
    }

    private static String resolveTestFixture(String classpathResource) {
        URL url = LocalClientRegistryProviderTest.class.getClassLoader().getResource(classpathResource);
        assertNotNull(url, "Test fixture not found on classpath: " + classpathResource);
        try {
            return Paths.get(url.toURI()).toString();
        } catch (URISyntaxException e) {
            throw new AssertionError("Invalid URI for classpath resource: " + classpathResource, e);
        }
    }
}
