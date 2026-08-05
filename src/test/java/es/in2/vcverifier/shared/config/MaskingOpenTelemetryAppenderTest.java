package es.in2.vcverifier.shared.config;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.LoggingEvent;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MaskingOpenTelemetryAppenderTest {

    // MASK is private in MaskingPatternLayout — redeclared here, same as MaskingPatternLayoutTest.
    private static final String MASK = "***REDACTED***";

    private static final String SAMPLE_JWT =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
                    + ".eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjoxNzAwMDAwMDAwfQ"
                    + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    // ─── Helper ───────────────────────────────────────────────────────────────

    private static LoggingEvent newEvent(String message) {
        LoggerContext loggerContext = new LoggerContext();
        loggerContext.start();
        ch.qos.logback.classic.Logger logger = loggerContext.getLogger("test-logger");
        return new LoggingEvent(
                MaskingOpenTelemetryAppenderTest.class.getName(),
                logger, Level.INFO, message, null, null
        );
    }

    // ─── getFormattedMessage() / getMessage() ─────────────────────────────────

    @Test
    void mask_FormattedMessageWithJwt_MasksJwt() {
        // Arrange
        LoggingEvent source = newEvent("Validating token: " + SAMPLE_JWT);

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getFormattedMessage())
                .contains(MASK)
                .doesNotContain(SAMPLE_JWT);
    }

    @Test
    void mask_MessageWithEmail_MasksEmail() {
        // Arrange
        LoggingEvent source = newEvent("Notifying admin@empresa.com");

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getMessage())
                .contains(MASK)
                .doesNotContain("admin@empresa.com");
    }

    // ─── getArgumentArray() ─────────────────────────────────────────────────────

    @Test
    void mask_ArgumentArray_IsNulledOutSoOriginalCannotBeReRendered() {
        // Arrange
        LoggingEvent source = newEvent("Notifying {}");
        source.setArgumentArray(new Object[]{"admin@empresa.com"});

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getArgumentArray()).isNull();
    }

    // ─── getMDCPropertyMap() / getMdc() ─────────────────────────────────────────

    @Test
    void mask_MdcValueIdentifiedOnlyByKeyName_MasksValue() {
        // Arrange — MaskingPatternLayout's sensitive-key pattern only fires when key and
        // value appear together as "key=value" in one string; an MDC map hands them over
        // as separate entries, so an opaque secret like this one carries no self-identifying
        // content (no JWT shape, no email) for the content-based patterns to catch.
        LoggingEvent source = newEvent("token exchange");
        source.setMDCPropertyMap(Map.of("secret", "oauth2ClientSecret"));

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getMDCPropertyMap())
                .containsKey("secret")
                .containsEntry("secret", MASK);
    }

    @Test
    void mask_MdcValueWithEmail_MasksValue() {
        // Arrange
        LoggingEvent source = newEvent("authenticated");
        source.setMDCPropertyMap(Map.of("userEmail", "admin@empresa.com"));

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getMDCPropertyMap()).containsEntry("userEmail", MASK);
    }

    @Test
    void mask_MdcValueWithNoSensitiveContent_LeavesValueUnchanged() {
        // Arrange
        LoggingEvent source = newEvent("tenant resolved");
        source.setMDCPropertyMap(Map.of("tenantDomain", "sandbox"));

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getMDCPropertyMap()).containsEntry("tenantDomain", "sandbox");
    }

    @Test
    void mask_DeprecatedGetMdcWithSecretValue_MasksValue() {
        // Arrange
        LoggingEvent source = newEvent("token exchange");
        source.setMDCPropertyMap(Map.of("access_token", "someAccessTokenValue"));

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getMdc()).containsEntry("access_token", MASK);
    }

    // ─── Unmasked passthrough ────────────────────────────────────────────────────

    @Test
    void mask_LoggerName_IsForwardedUnchanged() {
        // Arrange
        LoggingEvent source = newEvent("plain message");

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getLoggerName()).isEqualTo("test-logger");
    }
}
