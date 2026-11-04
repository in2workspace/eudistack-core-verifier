package es.in2.vcverifier.shared.config.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.LoggingEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import java.util.ArrayList;
import org.slf4j.event.KeyValuePair;

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

    // ─── Exceptions and key-value pairs ───────────────────────────────────────

    private static LoggingEvent failureEvent(Throwable failure) {
        LoggingEvent event = new LoggingEvent(MaskingOpenTelemetryAppenderTest.class.getName(),
                new LoggerContext().getLogger("test-logger"), Level.ERROR, "Send failed", failure, null);
        event.setMDCPropertyMap(Map.of());
        return event;
    }

    private static IllegalArgumentException failureChain() {
        IllegalArgumentException failure = new IllegalArgumentException(
                "Recipient holder@empresa.com rejected", new IllegalStateException("access_token=s3cr3tValue"));
        failure.addSuppressed(new IllegalStateException("Login other@empresa.com"));
        return failure;
    }

    private static Attributes export(LoggingEvent event) {
        List<LogRecordData> exported = new ArrayList<>();
        SdkLoggerProvider provider = SdkLoggerProvider.builder()
                .addLogRecordProcessor((context, logRecord) -> exported.add(logRecord.toLogRecordData()))
                .build();
        MaskingOpenTelemetryAppender appender = new MaskingOpenTelemetryAppender();
        appender.setCaptureKeyValuePairAttributes(true);
        appender.setOpenTelemetry(OpenTelemetrySdk.builder().setLoggerProvider(provider).build());
        appender.start();
        appender.append(event);
        return exported.get(0).getAttributes();
    }

    @Test
    void mask_ExceptionChain_MasksMessageCauseAndSuppressedKeepingTheFrames() {
        IThrowableProxy proxy = MaskingOpenTelemetryAppender.mask(failureEvent(failureChain())).getThrowableProxy();

        assertThat(proxy.getClassName()).isEqualTo(IllegalArgumentException.class.getName());
        assertThat(proxy.getMessage()).isEqualTo("Recipient " + MaskingPatternLayout.REPLACEMENT + " rejected");
        assertThat(proxy.getCause().getMessage()).isEqualTo("access_token=" + MaskingPatternLayout.REPLACEMENT);
        assertThat(proxy.getSuppressed()[0].getMessage()).isEqualTo("Login " + MaskingPatternLayout.REPLACEMENT);
        assertThat(proxy.getStackTraceElementProxyArray()).isNotEmpty();
        assertThat(ThrowableProxyUtil.asString(proxy))
                .contains("failureChain")
                .doesNotContain("holder@empresa.com", "s3cr3tValue", "other@empresa.com");
    }

    @Test
    void mask_ExceptionWithACircularCause_Terminates() {
        IllegalStateException first = new IllegalStateException("Login holder@empresa.com");
        IllegalStateException second = new IllegalStateException("Retry", first);
        first.initCause(second);

        IThrowableProxy proxy = MaskingOpenTelemetryAppender.mask(failureEvent(first)).getThrowableProxy();

        assertThat(ThrowableProxyUtil.asString(proxy)).doesNotContain("holder@empresa.com");
    }

    @Test
    void mask_EventWithoutException_HasNoThrowableProxy() {
        assertThat(MaskingOpenTelemetryAppender.mask(failureEvent(null)).getThrowableProxy()).isNull();
    }

    @Test
    void mask_KeyValuePairs_MasksSensitiveValuesAndKeepsNumbers() {
        LoggingEvent event = failureEvent(null);
        event.addKeyValuePair(new KeyValuePair("secret", "s3cr3tValue"));
        event.addKeyValuePair(new KeyValuePair("contact", "holder@empresa.com"));
        event.addKeyValuePair(new KeyValuePair("attempts", 3));
        event.addKeyValuePair(new KeyValuePair("missing", null));

        List<KeyValuePair> masked = MaskingOpenTelemetryAppender.mask(event).getKeyValuePairs();

        assertThat(masked).extracting(pair -> pair.key).containsExactly("secret", "contact", "attempts", "missing");
        assertThat(masked).extracting(pair -> pair.value)
                .containsExactly(MaskingPatternLayout.REPLACEMENT, MaskingPatternLayout.REPLACEMENT, 3, null);
    }

    @Test
    void mask_EventWithoutKeyValuePairs_HasNoPairs() {
        assertThat(MaskingOpenTelemetryAppender.mask(failureEvent(null)).getKeyValuePairs()).isEmpty();
    }

    @Test
    void append_ExceptionChain_ExportsTheExceptionAttributesMasked() {
        Attributes attributes = export(failureEvent(failureChain()));

        assertThat(attributes.get(AttributeKey.stringKey("exception.type")))
                .isEqualTo(IllegalArgumentException.class.getName());
        assertThat(attributes.get(AttributeKey.stringKey("exception.message")))
                .isEqualTo("Recipient " + MaskingPatternLayout.REPLACEMENT + " rejected");
        assertThat(attributes.get(AttributeKey.stringKey("exception.stacktrace")))
                .contains("failureChain")
                .doesNotContain("holder@empresa.com", "s3cr3tValue", "other@empresa.com");
    }

    @Test
    void append_ExceptionWithoutMessage_ExportsTypeAndStacktraceOnly() {
        Attributes attributes = export(failureEvent(new IllegalStateException()));

        assertThat(attributes.get(AttributeKey.stringKey("exception.type")))
                .isEqualTo(IllegalStateException.class.getName());
        assertThat(attributes.get(AttributeKey.stringKey("exception.message"))).isNull();
        assertThat(attributes.get(AttributeKey.stringKey("exception.stacktrace"))).isNotBlank();
    }

    @Test
    void append_EventWithoutException_ExportsNoExceptionAttributes() {
        LoggingEvent event = failureEvent(null);
        event.addKeyValuePair(new KeyValuePair("contact", "holder@empresa.com"));

        Attributes attributes = export(event);

        assertThat(attributes.get(AttributeKey.stringKey("contact"))).isEqualTo(MaskingPatternLayout.REPLACEMENT);
        assertThat(attributes.get(AttributeKey.stringKey("exception.type"))).isNull();
        assertThat(attributes.get(AttributeKey.stringKey("exception.stacktrace"))).isNull();
    }
}
