package es.in2.vcverifier.shared.domain.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogSanitizerTest {

    @Test
    void sanitize_nullValue_returnsNull() {
        // Arrange
        String value = null;

        // Act
        String result = LogSanitizer.sanitize(value);

        // Assert
        assertNull(result);
    }

    @Test
    void sanitize_valueWithCrLfAndTab_replacesEachWithUnderscore() {
        // Arrange
        String value = "legit\r\nSSO_AUDIT_EVENT {eventType=FORGED}\tvalue";

        // Act
        String result = LogSanitizer.sanitize(value);

        // Assert
        assertEquals("legit__SSO_AUDIT_EVENT {eventType=FORGED}_value", result);
    }

    @Test
    void sanitize_valueWithinLengthCap_isReturnedUnchanged() {
        // Arrange
        String value = "a".repeat(64);

        // Act
        String result = LogSanitizer.sanitize(value);

        // Assert
        assertEquals(value, result);
    }

    @Test
    void sanitize_valueLongerThanCap_isTruncatedWithSuffix() {
        // Arrange
        String value = "a".repeat(100);

        // Act
        String result = LogSanitizer.sanitize(value);

        // Assert
        assertEquals("a".repeat(64) + "...(truncated)", result);
        assertTrue(result.endsWith("...(truncated)"));
    }
}
