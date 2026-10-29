package es.in2.vcverifier.shared.infrastructure.audit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ConfiguredAuditAccessTokenProviderTest {

    @Test
    void accessToken_configuredToken_returnsIt() {
        // Arrange
        var provider = new ConfiguredAuditAccessTokenProvider("token-1");

        // Act & Assert
        assertEquals("token-1", provider.accessToken(null));
        assertEquals("token-1", provider.refreshAccessToken(null));
    }

    @Test
    void accessToken_blankToken_fails() {
        // Arrange
        var provider = new ConfiguredAuditAccessTokenProvider("");

        // Act & Assert
        assertThrows(IllegalStateException.class, () -> provider.accessToken(null));
    }
}
