package es.in2.vcverifier.sso;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.infrastructure.audit.SsoAuditAdapter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@SpringBootTest(classes = SsoAuditAdapter.class)
class SsoAuditResilienceIT {

    @Autowired
    private SsoAuditPort auditPort;

    private Logger logger;
    private ThrowingAppender appender;

    @BeforeEach
    void attachBrokenAppender() {
        logger = (Logger) LoggerFactory.getLogger(SsoAuditAdapter.class);
        appender = new ThrowingAppender();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        logger.detachAppender(appender);
    }

    @Test
    void publish_whenAppenderFails_doesNotPropagate() {
        assertDoesNotThrow(() -> {
            auditPort.publish(event(SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED));
            auditPort.publish(event(SsoAuditEvent.EventType.SSO_SESSION_REUSED));
            auditPort.publish(event(SsoAuditEvent.EventType.SSO_SESSION_EXPIRED));
            auditPort.publish(event(SsoAuditEvent.EventType.SSO_LOGOUT_INITIATED));
            auditPort.publish(event(SsoAuditEvent.EventType.SSO_BACKCHANNEL_DELIVERED));
            auditPort.publish(event(SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_ADDED));
        });
    }

    private static SsoAuditEvent event(SsoAuditEvent.EventType type) {
        return SsoAuditEvent.builder()
                .eventType(type)
                .tenant("tenantA").clientId("clientA").holderHash("sub-value")
                .outcome("OK").correlationId("corr-resilience").occurredAt(Instant.now())
                .build();
    }

    private static final class ThrowingAppender extends AppenderBase<ILoggingEvent> {
        @Override
        protected void append(ILoggingEvent eventObject) {
            throw new RuntimeException("appender down");
        }
    }
}
