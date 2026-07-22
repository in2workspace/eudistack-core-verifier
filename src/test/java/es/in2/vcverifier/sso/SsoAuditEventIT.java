package es.in2.vcverifier.sso;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = SsoAuditAdapter.class)
class SsoAuditEventIT {

    @Autowired
    private SsoAuditPort auditPort;

    private Logger logger;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void attachAppender() {
        logger = (Logger) LoggerFactory.getLogger(SsoAuditAdapter.class);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        logger.detachAppender(appender);
    }

    @Test
    void publishesEstablishedEvent_withFullDimension() {
        auditPort.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED)
                .tenant("tenantA").clientId("clientA").outcome("SUCCESS")
                .correlationId("corr-established").occurredAt(Instant.now()).build());

        assertThat(auditLine())
                .contains("eventType=SSO_SESSION_ESTABLISHED")
                .contains("tenant=tenantA")
                .contains("clientId=clientA")
                .contains("outcome=SUCCESS")
                .contains("correlationId=corr-established")
                .contains("occurredAt=");
    }

    @Test
    void publishesReusedEvent_distinguishesClientId() {
        auditPort.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_SESSION_REUSED)
                .tenant("tenantA").clientId("clientB").outcome("REUSED")
                .correlationId("corr-reused").occurredAt(Instant.now()).build());

        assertThat(auditLine())
                .contains("eventType=SSO_SESSION_REUSED")
                .contains("clientId=clientB")
                .contains("outcome=REUSED");
    }

    @Test
    void publishesExpiredEvent_withReason() {
        auditPort.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_SESSION_EXPIRED)
                .tenant("tenantA").outcome("EXPIRED").reason("absolute")
                .correlationId("corr-expired").occurredAt(Instant.now()).build());

        assertThat(auditLine())
                .contains("eventType=SSO_SESSION_EXPIRED")
                .contains("outcome=EXPIRED")
                .contains("reason=absolute");
    }

    @Test
    void publishesLogoutInitiatedEvent() {
        auditPort.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_LOGOUT_INITIATED)
                .tenant("tenantA").clientId("clientA").outcome("SUCCESS")
                .correlationId("corr-logout").occurredAt(Instant.now()).build());

        assertThat(auditLine())
                .contains("eventType=SSO_LOGOUT_INITIATED")
                .contains("clientId=clientA");
    }

    @Test
    void publishesBackchannelDeliveredEvent_perClientOutcome() {
        auditPort.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_BACKCHANNEL_DELIVERED)
                .tenant("tenantA").clientId("clientB").outcome("FAILED")
                .correlationId("corr-bc").occurredAt(Instant.now()).build());

        assertThat(auditLine())
                .contains("eventType=SSO_BACKCHANNEL_DELIVERED")
                .contains("clientId=clientB")
                .contains("outcome=FAILED");
    }

    private String auditLine() {
        List<String> lines = appender.list.stream()
                .filter(e -> e.getLevel() == Level.INFO)
                .map(ILoggingEvent::getFormattedMessage)
                .filter(m -> m.startsWith("SSO_AUDIT_EVENT"))
                .toList();
        assertThat(lines).hasSize(1);
        return lines.get(0);
    }
}
