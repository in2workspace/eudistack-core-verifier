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

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = SsoAuditAdapter.class)
class SsoAuditPiiRedactionIT {

    private static final String RAW_SUB = "did:key:z6MkVerySensitiveSubjectValueABCDEF0123456789";

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
    void neverLogsRawSubForAnyEventType() {
        for (SsoAuditEvent.EventType type : SsoAuditEvent.EventType.values()) {
            auditPort.publish(SsoAuditEvent.builder()
                    .eventType(type)
                    .tenant("tenantA").clientId("clientA").holderHash(RAW_SUB)
                    .outcome("OK").correlationId("corr-pii").occurredAt(Instant.now()).build());
        }

        assertThat(auditLines()).isNotEmpty();
        for (String line : auditLines()) {
            assertThat(line).doesNotContain(RAW_SUB);
        }
    }

    @Test
    void emitsSubAsOneWayHash() {
        auditPort.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED)
                .tenant("tenantA").clientId("clientA").holderHash(RAW_SUB)
                .outcome("SUCCESS").correlationId("corr-hash").occurredAt(Instant.now()).build());

        String line = auditLines().get(0);
        assertThat(line).doesNotContain(RAW_SUB);
        assertThat(line).containsPattern("sub=[0-9a-f]{16}");
    }

    private java.util.List<String> auditLines() {
        return appender.list.stream()
                .filter(e -> e.getLevel() == Level.INFO)
                .map(ILoggingEvent::getFormattedMessage)
                .filter(m -> m.startsWith("SSO_AUDIT_EVENT"))
                .toList();
    }
}
