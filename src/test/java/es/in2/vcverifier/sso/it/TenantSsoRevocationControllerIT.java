package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.oauth2.infrastructure.filter.CustomErrorResponseHandler;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "spring.flyway.enabled=false",
        "verifier.backend.url=https://localhost",
        "verifier.frontend.portalUrl=https://localhost",
        "spring.security.oauth2.authorizationserver.endpoint.authorization-uri-validation=false"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class TenantSsoRevocationControllerIT {

    private static final String TENANT   = "tenant-1";
    private static final String TENANT_2 = "tenant-2";
    private static final String LEGACY   = "legacy-tenant";
    private static final String X_TENANT = "X-Tenant";
    private static final String URL      = "/tenant/sso/revoke";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SsoSessionRepositoryPort ssoSessionRepositoryPort;

    @MockitoBean
    private SsoAuditPort auditPort;

    @MockitoBean private TenantSsoConfigPort tenantSsoConfigPort;
    @MockitoBean private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;
    @MockitoBean private ClientLoaderConfig clientLoaderConfig;
    @MockitoBean private RegisteredClientRepository registeredClientRepository;
    @MockitoBean private DcqlProfileResolver dcqlProfileResolver;
    @MockitoBean private CustomErrorResponseHandler customErrorResponseHandler;
    @MockitoBean private ClientRegistryProvider clientRegistryProvider;

    @BeforeEach
    void setUp() {
        reset(auditPort, ssoSessionRepositoryPort);
    }

    @Test
    void shouldrReturn200WithCountAndAuditSuccess_whenSessionsExist() throws Exception {
        // Given
        when(ssoSessionRepositoryPort.revokeAllByTenant(TENANT)).thenReturn(5);

        // When / Then
        mockMvc.perform(post(URL)
                        .header(X_TENANT, TENANT)
                        .with(authentication(adminAuth(TENANT)))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count_revoked").value(5));

        verify(ssoSessionRepositoryPort).revokeAllByTenant(eq(TENANT));
        verify(auditPort).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.EMERGENCY_REVOKE
                        && TENANT.equals(event.getTenant())
                        && event.getCountRevoked() != null && event.getCountRevoked() == 5
                        && "success".equals(event.getOutcome())
                        && event.getCorrelationId() != null));
    }

    @Test
    void shouldReturn200WithZeroCount_whenNoSessions() throws Exception {
        // Given
        when(ssoSessionRepositoryPort.revokeAllByTenant(TENANT)).thenReturn(0);

        // When / Then
        mockMvc.perform(post(URL)
                        .header(X_TENANT, TENANT)
                        .with(authentication(adminAuth(TENANT)))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count_revoked").value(0));

        verify(auditPort).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.EMERGENCY_REVOKE
                        && event.getCountRevoked() != null && event.getCountRevoked() == 0
                        && "success".equals(event.getOutcome())));
    }

    @Test
    void should_propagateCorrelationId_toAuditEvent() throws Exception {
        // Given
        String correlationId = "corr-fixed-12345";
        when(ssoSessionRepositoryPort.revokeAllByTenant(TENANT)).thenReturn(2);

        // When / Then
        mockMvc.perform(post(URL)
                        .header(X_TENANT, TENANT)
                        .header("X-Correlation-Id", correlationId)
                        .with(authentication(adminAuth(TENANT)))
                        .with(csrf()))
                .andExpect(status().isOk());

        verify(auditPort).publish(argThat(event ->
                correlationId.equals(event.getCorrelationId())));
    }

    @Test
    void should_beIdempotent_onDoubleCut() throws Exception {
        // Given
        when(ssoSessionRepositoryPort.revokeAllByTenant(TENANT))
                .thenReturn(3)
                .thenReturn(0);

        // When / Then
        mockMvc.perform(post(URL).header(X_TENANT, TENANT)
                        .with(authentication(adminAuth(TENANT))).with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count_revoked").value(3));

        mockMvc.perform(post(URL).header(X_TENANT, TENANT)
                        .with(authentication(adminAuth(TENANT))).with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count_revoked").value(0));

        verify(ssoSessionRepositoryPort, org.mockito.Mockito.times(2)).revokeAllByTenant(eq(TENANT));
    }

    @Test
    void shouldReturn200WithZeroCount_forLegacyTenant() throws Exception {
        // Given
        when(ssoSessionRepositoryPort.revokeAllByTenant(LEGACY)).thenReturn(0);

        // When / Then
        mockMvc.perform(post(URL)
                        .header(X_TENANT, LEGACY)
                        .with(authentication(adminAuth(LEGACY)))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count_revoked").value(0));
    }

    @Test
    void shouldReturn4xxAndNotRevoke_whenUnauthenticated() throws Exception {
        // When / Then
        mockMvc.perform(post(URL)
                        .header(X_TENANT, TENANT)
                        .with(csrf()))
                .andExpect(status().is4xxClientError());

        verify(ssoSessionRepositoryPort, never()).revokeAllByTenant(anyString());
        verify(auditPort, never()).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.EMERGENCY_REVOKE));
    }

    @Test
    void shouldReturn403AndNotRevoke_onCrossTenant() throws Exception {
        // Given
        // When / Then
        mockMvc.perform(post(URL)
                        .header(X_TENANT, TENANT_2)
                        .with(authentication(adminAuth(TENANT)))
                        .with(csrf()))
                .andExpect(status().isForbidden());

        verify(ssoSessionRepositoryPort, never()).revokeAllByTenant(anyString());
    }

    // --- helpers ---

    private static UsernamePasswordAuthenticationToken adminAuth(String tenant) {
        return new UsernamePasswordAuthenticationToken(
                Map.of("tenant", tenant),
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
    }
}
