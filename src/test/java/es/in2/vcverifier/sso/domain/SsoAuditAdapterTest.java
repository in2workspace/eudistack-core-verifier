package es.in2.vcverifier.sso.domain;

import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.infrastructure.audit.SsoAuditAdapter;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class SsoAuditAdapterTest {

    private final SsoAuditAdapter adapter = new SsoAuditAdapter();

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

    @Test
    void should_handle_session_established_event() {

        SsoAuditEvent event = new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED,
                "tenantA",
                "clientA",
                "sub-value",
                "SUCCESS",
                "corr-1",
                Instant.now()
        );

        assertDoesNotThrow(() -> adapter.publish(event));
    }

    @Test
    void should_handle_establish_failed_event() {

        SsoAuditEvent event = new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED,
                "tenantA",
                "clientA",
                "sub-value",
                "FAILURE",
                "corr-2",
                Instant.now()
        );

        assertDoesNotThrow(() -> adapter.publish(event));
    }

    @Test
    void should_handle_cross_tenant_attempt_event() {

        SsoAuditEvent event = new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_CROSS_TENANT_ATTEMPT,
                "tenantA",
                "clientA",
                "sub-value",
                "DENIED",
                "corr-3",
                Instant.now()
        );

        assertDoesNotThrow(() -> adapter.publish(event));
    }
}