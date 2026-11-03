package es.in2.vcverifier.shared.config.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.LoggingEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class MaskingOpenTelemetryAppenderTest {

    private static final String MASK = MaskingPatternLayout.REPLACEMENT;

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
    void mask_ArgumentArray_IsEmptiedSoOriginalCannotBeReRendered() {
        // Arrange
        LoggingEvent source = newEvent("Notifying {}");
        source.setArgumentArray(new Object[]{"admin@empresa.com"});

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getArgumentArray()).isEmpty();
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

    @Test
    void mask_NullMdc_ReturnsEmptyMap() {
        // Arrange
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getMDCPropertyMap()).thenReturn(null);

        // Act & Assert
        assertThat(MaskingOpenTelemetryAppender.mask(source).getMDCPropertyMap()).isEmpty();
    }

    // ─── Unmasked passthrough ────────────────────────────────────────────────────

    @Test
    void mask_EveryOtherAccessor_IsForwardedUnchanged() {
        // Arrange
        ILoggingEvent source = mock(ILoggingEvent.class);
        Instant now = Instant.now();
        when(source.getLoggerName()).thenReturn("test-logger");
        when(source.getThreadName()).thenReturn("virtual-3");
        when(source.getLevel()).thenReturn(Level.INFO);
        when(source.getTimeStamp()).thenReturn(now.toEpochMilli());
        when(source.getInstant()).thenReturn(now);
        when(source.getNanoseconds()).thenReturn(42);
        when(source.getSequenceNumber()).thenReturn(7L);
        when(source.hasCallerData()).thenReturn(true);
        when(source.getMarkerList()).thenReturn(List.of());
        when(source.getKeyValuePairs()).thenReturn(List.of());

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);
        masked.prepareForDeferredProcessing();

        // Assert
        assertThat(masked.getLoggerName()).isEqualTo("test-logger");
        assertThat(masked.getThreadName()).isEqualTo("virtual-3");
        assertThat(masked.getLevel()).isEqualTo(Level.INFO);
        assertThat(masked.getTimeStamp()).isEqualTo(now.toEpochMilli());
        assertThat(masked.getInstant()).isEqualTo(now);
        assertThat(masked.getNanoseconds()).isEqualTo(42);
        assertThat(masked.getSequenceNumber()).isEqualTo(7L);
        assertThat(masked.hasCallerData()).isTrue();
        assertThat(masked.getMarkerList()).isEmpty();
        assertThat(masked.getKeyValuePairs()).isEmpty();
        assertThat(masked.getLoggerContextVO()).isNull();
        assertThat(masked.getThrowableProxy()).isNull();
        assertThat(masked.getCallerData()).isNull();
        verify(source).prepareForDeferredProcessing();
    }
}
