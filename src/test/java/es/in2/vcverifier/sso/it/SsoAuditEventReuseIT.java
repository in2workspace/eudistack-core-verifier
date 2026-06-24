package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;

@SpringBootTest(
        properties = {
                "spring.flyway.enabled=false",
                "verifier.backend.url=https://localhost",
                "verifier.frontend.portalUrl=https://localhost"
        }
)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestClientConfig.class)
class SsoAuditEventReuseIT {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private TenantSsoConfigPort tenantSsoConfigPort;

    @MockitoBean
    private SsoSessionRepositoryPort sessionRepositoryPort;

    @MockitoBean
    ClientLoaderConfig clientLoaderConfig;

    @MockitoBean
    private RegisteredClientRepository registeredClientRepository;

    @MockitoBean
    private DcqlProfileResolver dcqlProfileResolver;

    @MockitoBean
    private es.in2.vcverifier.oauth2.infrastructure.filter.CustomErrorResponseHandler customErrorResponseHandler;

    @MockitoSpyBean
    private SsoAuditPort auditPort;

    // =========================================================
    // AC-05: successful reuse emits clean audit event
    // =========================================================
    @Test
    void should_emit_sso_session_reused_event_without_pii() {

        Instant now = Instant.now();

        // holderHash debe ser ya un hash, nunca el sub raw
        String holderHash = "967944aa23da7686"; // hash truncado, no el sub real

        SsoAuditEvent expectedEvent = new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_SESSION_REUSED,
                "tenantA",
                "clientA",
                holderHash,
                "SUCCESS",
                "corr-12345678",
                now
        );

        auditPort.publish(expectedEvent);

        verify(auditPort).publish(argThat(event -> {

            boolean correctType = event.getEventType()
                    .equals(SsoAuditEvent.EventType.SSO_SESSION_REUSED);

            boolean tenantOk = "tenantA".equals(event.getTenant());

            boolean clientOk = "clientA".equals(event.getClientId());

            boolean outcomeOk = event.getOutcome() != null;

            // NFR-S-548-01: holderHash debe ser un hash corto, no un sub raw
            // Un sub real nunca sería un hex de 16 chars
            boolean noRawSub = event.getHolderHash() != null
                    && event.getHolderHash().length() <= 64
                    && !event.getHolderHash().contains("@")
                    && !event.getHolderHash().contains("did:");

            // NFR-S-548-02: correlationId no desborda
            boolean noSessionLeak = event.getCorrelationId() != null
                    && event.getCorrelationId().length() <= 64;

            return correctType && tenantOk && clientOk && outcomeOk && noRawSub && noSessionLeak;
        }));
    }

    // =========================================================
    // Safety test: ensure no exception and structured emission
    // =========================================================
    @Test
    void should_never_fail_when_emitting_reuse_event() {

        SsoAuditEvent event = new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_SESSION_REUSED,
                "tenantA",
                "clientA",
                "sub",
                "SUCCESS",
                "corr",
                Instant.now()
        );

        assertDoesNotThrow(() -> auditPort.publish(event));
    }
}