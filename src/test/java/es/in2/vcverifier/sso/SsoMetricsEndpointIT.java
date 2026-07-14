package es.in2.vcverifier.sso;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.oauth2.infrastructure.filter.CustomErrorResponseHandler;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.SsoTenantMetrics;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.sso.domain.port.SsoMetricsPort;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
class SsoMetricsEndpointIT {

    private static final String TENANT   = "tenant-a";
    private static final String X_TENANT = "X-Tenant";
    private static final String URL      = "/tenant/sso/metrics";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SsoMetricsPort metricsPort;

    @MockitoBean private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;
    @MockitoBean private SsoAuditPort auditPort;
    @MockitoBean private TenantSsoConfigPort tenantSsoConfigPort;
    @MockitoBean private ClientLoaderConfig clientLoaderConfig;
    @MockitoBean private RegisteredClientRepository registeredClientRepository;
    @MockitoBean private DcqlProfileResolver dcqlProfileResolver;
    @MockitoBean private CustomErrorResponseHandler customErrorResponseHandler;
    @MockitoBean private ClientRegistryProvider clientRegistryProvider;

    @Test
    void should_return200_withMetricsForAuthenticatedTenant() throws Exception {
        SsoTenantMetrics metrics = SsoTenantMetrics.of(TENANT, 100, 250, 250,
                Map.of("clientB", new SsoTenantMetrics.ClientReuseMetrics("clientB", 250)));
        when(metricsPort.metricsFor(TENANT)).thenReturn(metrics);

        mockMvc.perform(get(URL)
                        .header(X_TENANT, TENANT)
                        .accept(MediaType.APPLICATION_JSON)
                        .with(authentication(adminAuth(TENANT)))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenant").value(TENANT))
                .andExpect(jsonPath("$.establishedTotal").value(100))
                .andExpect(jsonPath("$.reuseTotal").value(250))
                .andExpect(jsonPath("$.oid4vpAvoidedTotal").value(250))
                .andExpect(jsonPath("$.reuseRatio").value(2.5))
                .andExpect(jsonPath("$.byClientId.clientB.reuseTotal").value(250));
    }

    @Test
    void should_return200_withZeros_whenTenantHasNoActivity() throws Exception {
        when(metricsPort.metricsFor(TENANT))
                .thenReturn(SsoTenantMetrics.of(TENANT, 0, 0, 0, Map.of()));

        mockMvc.perform(get(URL)
                        .header(X_TENANT, TENANT)
                        .accept(MediaType.APPLICATION_JSON)
                        .with(authentication(adminAuth(TENANT)))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.establishedTotal").value(0))
                .andExpect(jsonPath("$.reuseTotal").value(0))
                .andExpect(jsonPath("$.oid4vpAvoidedTotal").value(0))
                .andExpect(jsonPath("$.reuseRatio").doesNotExist());
    }

    private static UsernamePasswordAuthenticationToken adminAuth(String tenant) {
        return new UsernamePasswordAuthenticationToken(
                Map.of("tenant", tenant),
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    }
}
