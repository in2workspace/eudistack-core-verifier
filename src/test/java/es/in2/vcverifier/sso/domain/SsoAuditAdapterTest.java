package es.in2.vcverifier.sso.domain;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.infrastructure.audit.SsoAuditAdapter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SsoAuditAdapterTest {

    private final SsoAuditAdapter adapter = new SsoAuditAdapter();

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
    void SsoAuditAdapter_publish_structuresEstablishedEvent() {
        adapter.publish(new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED,
                "tenantA",
                "clientA",
                "sub-value",
                "SUCCESS",
                "corr-1",
                Instant.now()
        ));

        String line = singleAuditEvent();
        assertThat(line)
                .contains("eventType=SSO_SESSION_ESTABLISHED")
                .contains("tenant=tenantA")
                .contains("clientId=clientA")
                .contains("outcome=SUCCESS")
                .contains("correlationId=corr-1")
                .contains("occurredAt=");
    }

    @Test
    void SsoAuditAdapter_publish_structuresReusedEvent() {
        adapter.publish(new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_SESSION_REUSED,
                "tenantA",
                "clientB",
                "sub-value",
                "REUSED",
                "corr-2",
                Instant.now()
        ));

        assertThat(singleAuditEvent())
                .contains("eventType=SSO_SESSION_REUSED")
                .contains("clientId=clientB")
                .contains("outcome=REUSED");
    }

    @Test
    void SsoAuditAdapter_publish_structuresExpiredEvent() {
        adapter.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_SESSION_EXPIRED)
                .tenant("tenantA")
                .outcome("EXPIRED")
                .reason("absolute")
                .correlationId("corr-3")
                .occurredAt(Instant.now())
                .build());

        assertThat(singleAuditEvent())
                .contains("eventType=SSO_SESSION_EXPIRED")
                .contains("outcome=EXPIRED")
                .contains("reason=absolute");
    }

    @Test
    void SsoAuditAdapter_publish_structuresLogoutInitiatedEvent() {
        adapter.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_LOGOUT_INITIATED)
                .tenant("tenantA")
                .clientId("clientA")
                .outcome("SUCCESS")
                .correlationId("corr-4")
                .occurredAt(Instant.now())
                .build());

        assertThat(singleAuditEvent())
                .contains("eventType=SSO_LOGOUT_INITIATED")
                .contains("clientId=clientA")
                .contains("outcome=SUCCESS");
    }

    @Test
    void SsoAuditAdapter_publish_structuresBackchannelDeliveredEvent() {
        adapter.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_BACKCHANNEL_DELIVERED)
                .tenant("tenantA")
                .clientId("clientB")
                .outcome("FAILED")
                .correlationId("corr-5")
                .occurredAt(Instant.now())
                .build());

        assertThat(singleAuditEvent())
                .contains("eventType=SSO_BACKCHANNEL_DELIVERED")
                .contains("clientId=clientB")
                .contains("outcome=FAILED");
    }

    @Test
    void SsoAuditAdapter_publish_neverLogsPlainSubNorFullSessionId() {
        String rawSub = "did:key:z6MkVerySensitiveSubjectValue0123456789";

        adapter.publish(new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED,
                "tenantA",
                "clientA",
                rawSub,
                "SUCCESS",
                "corr-6",
                Instant.now()
        ));

        String line = singleAuditEvent();

        assertThat(line).doesNotContain(rawSub);
        assertThat(line).containsPattern("sub=[0-9a-f]{16}");
    }

    @Test
    void SsoAuditAdapter_publish_nullClientId_doesNotBreakStructure() {
        assertDoesNotThrow(() -> adapter.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_SESSION_EXPIRED)
                .tenant("tenantA")
                .clientId(null)
                .outcome("EXPIRED")
                .correlationId("corr-7")
                .occurredAt(Instant.now())
                .build()));

        assertThat(singleAuditEvent())
                .contains("eventType=SSO_SESSION_EXPIRED")
                .contains("clientId=null");
    }

    @Test
    void SsoAuditAdapter_publish_loggingFailure_doesNotPropagate() {
        SsoAuditEvent faulty = mock(SsoAuditEvent.class);
        when(faulty.getEventType()).thenReturn(SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED);
        when(faulty.getTenant()).thenReturn("tenantA");
        when(faulty.getOutcome()).thenReturn("SUCCESS");
        when(faulty.getClientId()).thenReturn("clientA");
        when(faulty.getCorrelationId()).thenReturn("corr-8");
        when(faulty.getOccurredAt()).thenReturn(Instant.now());
        when(faulty.getHolderHash()).thenThrow(new RuntimeException("serialization boom"));

        assertDoesNotThrow(() -> adapter.publish(faulty));

        assertThat(auditEventLines()).isEmpty();
        assertThat(errorLines())
                .anySatisfy(line -> assertThat(line)
                        .contains("SSO_AUDIT_EMISSION_FAILED")
                        .doesNotContain("serialization boom"));
    }

    @Test
    void SsoAuditAdapter_publish_missingMandatoryField_bestEffortNoLoss() {
        adapter.publish(new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED,
                null,
                "clientA",
                "sub-value",
                null,
                "corr-9",
                Instant.now()
        ));

        assertThat(singleAuditEvent())
                .contains("tenant=unknown")
                .contains("outcome=unknown")
                .contains("anomaly=missing_mandatory_field");
    }

    @Test
    void should_publish_all_sso_event_types_without_errors() {

        for (SsoAuditEvent.EventType type : SsoAuditEvent.EventType.values()) {

            SsoAuditEvent event = new SsoAuditEvent(
                    type,
                    "tenantA",
                    "clientA",
                    "very-sensitive-sub",
                    "OK",
                    "correlation-12345678-abcdef",
                    Instant.now()
            );

            assertDoesNotThrow(() -> adapter.publish(event));
        }
    }

    // ─── helpers ───

    private List<String> auditEventLines() {
        return appender.list.stream()
                .filter(e -> e.getLevel() == Level.INFO)
                .map(ILoggingEvent::getFormattedMessage)
                .filter(m -> m.startsWith("SSO_AUDIT_EVENT"))
                .toList();
    }

    private List<String> errorLines() {
        return appender.list.stream()
                .filter(e -> e.getLevel() == Level.ERROR)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    private String singleAuditEvent() {
        List<String> lines = auditEventLines();
        assertThat(lines).hasSize(1);
        return lines.get(0);
    }
}
