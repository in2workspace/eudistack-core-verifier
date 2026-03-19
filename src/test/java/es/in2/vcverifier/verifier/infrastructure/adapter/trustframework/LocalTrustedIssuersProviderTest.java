package es.in2.vcverifier.verifier.infrastructure.adapter.trustframework;

import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;
import org.junit.jupiter.api.Test;

import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalTrustedIssuersProviderTest {

    @Test
    void knownIssuer_returnsCapabilities() {
        // The default local/trusted-issuers.yaml has VATES-A15456585
        LocalTrustedIssuersProvider provider = new LocalTrustedIssuersProvider();

        List<IssuerCredentialsCapabilities> capabilities = provider.getIssuerCapabilities("VATES-A15456585");

        assertNotNull(capabilities);
        assertFalse(capabilities.isEmpty());
        assertTrue(capabilities.stream().anyMatch(c -> "learcredential.employee.w3c.4".equals(c.credentialsType())));
        assertTrue(capabilities.stream().anyMatch(c -> "learcredential.machine.w3c.3".equals(c.credentialsType())));
        assertTrue(capabilities.stream().anyMatch(c -> "gx.labelcredential.w3c.1".equals(c.credentialsType())));
    }

    @Test
    void unknownIssuer_throwsException() {
        LocalTrustedIssuersProvider provider = new LocalTrustedIssuersProvider();

        assertThrows(IssuerNotAuthorizedException.class,
                () -> provider.getIssuerCapabilities("UNKNOWN-ISSUER"));
    }

    @Test
    void missingFile_fallsBackToClasspath() {
        LocalTrustedIssuersProvider provider = new LocalTrustedIssuersProvider("/nonexistent/file.yaml");

        // When external file is missing, falls back to classpath resource
        List<IssuerCredentialsCapabilities> capabilities = provider.getIssuerCapabilities("VATES-A15456585");
        assertNotNull(capabilities);
        assertFalse(capabilities.isEmpty());
    }

    @Test
    void externalFile_returnsCapabilities() {
        String path = resolveTestFixture("test-fixtures/specific-issuers.yaml");
        LocalTrustedIssuersProvider provider = new LocalTrustedIssuersProvider(path);

        List<IssuerCredentialsCapabilities> capabilities = provider.getIssuerCapabilities("VATES-12345678");

        assertNotNull(capabilities);
        assertEquals(1, capabilities.size());
        assertEquals("learcredential.employee.w3c.4", capabilities.get(0).credentialsType());
    }

    @Test
    void externalFile_unknownIssuer_throwsException() {
        String path = resolveTestFixture("test-fixtures/specific-issuers.yaml");
        LocalTrustedIssuersProvider provider = new LocalTrustedIssuersProvider(path);

        assertThrows(IssuerNotAuthorizedException.class,
                () -> provider.getIssuerCapabilities("UNKNOWN"));
    }

    private static String resolveTestFixture(String classpathResource) {
        URL url = LocalTrustedIssuersProviderTest.class.getClassLoader().getResource(classpathResource);
        assertNotNull(url, "Test fixture not found on classpath: " + classpathResource);
        try {
            return Paths.get(url.toURI()).toString();
        } catch (URISyntaxException e) {
            throw new AssertionError("Invalid URI for classpath resource: " + classpathResource, e);
        }
    }
}