package es.in2.vcverifier.shared.config;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.instrumentation.logback.appender.v1_0.OpenTelemetryAppender;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;

/**
 * Injects the Spring-managed {@link OpenTelemetry} instance into the Logback appender.
 * Logback starts before the Spring context, so {@code MaskingOpenTelemetryAppender} has no
 * SDK to export to until this runs; every log record emitted meanwhile is silently dropped
 * (buffered up to a limit, then discarded — see OpenTelemetryAppender#install javadoc).
 */
@Component
@RequiredArgsConstructor
public class OpenTelemetryAppenderInitializer implements InitializingBean {

    private final OpenTelemetry openTelemetry;

    @Override
    public void afterPropertiesSet() {
        OpenTelemetryAppender.install(openTelemetry);
    }
}
