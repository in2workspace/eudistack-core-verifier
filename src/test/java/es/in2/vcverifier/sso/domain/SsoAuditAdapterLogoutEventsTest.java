package es.in2.vcverifier.sso.domain;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.infrastructure.audit.SsoAuditAdapter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.slf4j.LoggerFactory;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * US-06 / Task 13 — NFR-S-551-01, NFR-S-551-02: los 6 nuevos tipos de evento del flujo
 * de Single Logout deben estructurar correctamente sus campos y NUNCA loggear el {@code sub}
 * en claro ni el {@code sessionId} completo (solo un prefijo de 8 chars).
 */
class SsoAuditAdapterLogoutEventsTest {

    private static final String RAW_SUBJECT = "did:example:very-sensitive-subject-12345";
    private static final String RAW_SESSION_ID = "8f14e45f-ceea-467e-bd42-ffffffffffff";

    private final SsoAuditAdapter adapter = new SsoAuditAdapter();

    private ListAppender<ILoggingEvent> logAppender;
    private Logger adapterLogger;

    @BeforeEach
    void setUp() {
        adapterLogger = (Logger) LoggerFactory.getLogger(SsoAuditAdapter.class);
        logAppender = new ListAppender<>();
        logAppender.start();
        adapterLogger.addAppender(logAppender);
    }

    @AfterEach
    void tearDown() {
        adapterLogger.detachAppender(logAppender);
        logAppender.stop();
    }

    @ParameterizedTest
    @EnumSource(value = SsoAuditEvent.EventType.class, names = {
            "SSO_LOGOUT_INITIATED",
            "BACKCHANNEL_DELIVERED",
            "BACKCHANNEL_FAILED",
            "BACKCHANNEL_SKIPPED",
            "SSO_LOGOUT_REJECTED",
            "SSO_LOGOUT_STORE_ERROR"
    })
    void publish_logoutEvent_neverLogsRawSubjectOrFullSessionId(SsoAuditEvent.EventType type) {
        SsoAuditEvent event = SsoAuditEvent.builder()
                .eventType(type)
                .tenant("tenantA")
                .clientId("clientA")
                .holderHash(RAW_SUBJECT)
                .outcome("OK")
                .correlationId("corr-logout-1")
                .occurredAt(Instant.now())
                .sessionId(RAW_SESSION_ID)
                .build();

        adapter.publish(event);

        String formatted = lastFormattedMessage();

        assertThat(formatted)
                .as("event=%s no debe loggear el sub en claro", type)
                .doesNotContain(RAW_SUBJECT);
        assertThat(formatted)
                .as("event=%s no debe loggear el sessionId completo", type)
                .doesNotContain(RAW_SESSION_ID);
        assertThat(formatted)
                .as("event=%s debe loggear el prefijo de 8 chars del sessionId", type)
                .contains(RAW_SESSION_ID.substring(0, 8));
    }

    @ParameterizedTest
    @EnumSource(value = SsoAuditEvent.EventType.class, names = {
            "SSO_LOGOUT_INITIATED",
            "BACKCHANNEL_DELIVERED",
            "BACKCHANNEL_FAILED",
            "BACKCHANNEL_SKIPPED",
            "SSO_LOGOUT_REJECTED",
            "SSO_LOGOUT_STORE_ERROR"
    })
    void publish_logoutEvent_structuresCoreFields(SsoAuditEvent.EventType type) {
        SsoAuditEvent event = SsoAuditEvent.builder()
                .eventType(type)
                .tenant("tenantA")
                .clientId("clientB")
                .holderHash(RAW_SUBJECT)
                .outcome("OK")
                .correlationId("corr-logout-2")
                .occurredAt(Instant.now())
                .sessionId(RAW_SESSION_ID)
                .build();

        adapter.publish(event);

        String formatted = lastFormattedMessage();

        assertThat(formatted).contains(type.name());
        assertThat(formatted).contains("tenantA");
        assertThat(formatted).contains("clientB");
        assertThat(formatted).contains("corr-logout-2");
    }

    @Test
    void publish_logoutEvent_omitsSessionIdPrefixWhenSessionIdIsNull() {
        SsoAuditEvent event = SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_LOGOUT_REJECTED)
                .tenant("tenantA")
                .clientId("clientA")
                .holderHash(RAW_SUBJECT)
                .outcome("REJECTED")
                .correlationId("corr-logout-3")
                .occurredAt(Instant.now())
                .build();

        adapter.publish(event);

        String formatted = lastFormattedMessage();

        assertThat(formatted).contains("sessionIdPrefix=null");
    }

    private String lastFormattedMessage() {
        assertThat(logAppender.list).isNotEmpty();
        return logAppender.list.get(logAppender.list.size() - 1).getFormattedMessage();
    }
}
