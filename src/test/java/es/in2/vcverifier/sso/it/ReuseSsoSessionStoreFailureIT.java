package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.domain.model.AuthorizationContext;
import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.application.workflow.ReuseSsoSessionWorkflow;
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
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

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
class ReuseSsoSessionStoreFailureIT {

    @Autowired
    private ReuseSsoSessionWorkflow workflow;

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private TenantSsoConfigPort tenantSsoConfigPort;

    @MockitoBean
    private SsoSessionRepositoryPort sessionRepositoryPort;

    @MockitoBean
    private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;

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
    // ES-01: repository failure → fail closed
    // =========================================================
    @Test
    void should_return_login_required_when_store_fails() {

        // Configura el tenant para que el workflow no falle antes de llegar al repositorio
        when(tenantSsoConfigPort.getByTenant("tenantA"))
                .thenReturn(Optional.of(new es.in2.vcverifier.shared.domain.model.TenantSsoConfig(
                        "tenantA",
                        "domain",
                        true,
                        new es.in2.vcverifier.shared.domain.model.TenantSsoConfig.SsoTtlConfig(
                                java.time.Duration.ofHours(1),
                                java.time.Duration.ofMinutes(10)
                        ),
                        List.of(es.in2.vcverifier.shared.domain.model.EligibleClientConfig.of("clientA"))
                )));

        when(sessionRepositoryPort.findActiveById(any(), any()))
                .thenThrow(new RuntimeException("DB timeout"));

        AuthorizationContext ctx = mock(AuthorizationContext.class);
        String sessionId = UUID.randomUUID().toString();

        ReuseSsoSessionWorkflow.Result result = workflow.reuse(
                "tenantA",
                sessionId,
                ctx,
                "clientA"
        );

        assertNotNull(result);
        assertEquals(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED, result.status());

        verify(auditPort, atLeastOnce()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_PERSIST_ERROR &&
                        "tenantA".equals(event.getTenant())
        ));
    }
}