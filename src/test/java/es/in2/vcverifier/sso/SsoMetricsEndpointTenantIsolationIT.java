package es.in2.vcverifier.sso;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.oauth2.infrastructure.filter.CustomErrorResponseHandler;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
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

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "spring.flyway.enabled=false",
        "verifier.backend.url=https://localhost",
        "verifier.frontend.portalUrl=https://localhost",
        "spring.security.oauth2.authorizationserver.endpoint.authorization-uri-validation=false"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SsoMetricsEndpointTenantIsolationIT {

    private static final String TENANT_A = "tenant-a";
    private static final String TENANT_B = "tenant-b";
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
    void should_return403_whenAuthTenantDiffersFromRequestTenant() throws Exception {
        mockMvc.perform(get(URL)
                        .header(X_TENANT, TENANT_B)
                        .accept(MediaType.APPLICATION_JSON)
                        .with(authentication(adminAuth(TENANT_A)))
                        .with(csrf()))
                .andExpect(status().isForbidden());

        verify(metricsPort, never()).metricsFor(anyString());
    }

    @Test
    void should_return4xx_whenUnauthenticated() throws Exception {
        mockMvc.perform(get(URL)
                        .header(X_TENANT, TENANT_A)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().is4xxClientError());

        verify(metricsPort, never()).metricsFor(anyString());
    }

    @Test
    void should_return403_whenAuthenticatedWithoutAdminRole() throws Exception {
        UsernamePasswordAuthenticationToken nonAdmin = new UsernamePasswordAuthenticationToken(
                Map.of("tenant", TENANT_A), null, List.of(new SimpleGrantedAuthority("ROLE_USER")));

        mockMvc.perform(get(URL)
                        .header(X_TENANT, TENANT_A)
                        .accept(MediaType.APPLICATION_JSON)
                        .with(authentication(nonAdmin))
                        .with(csrf()))
                .andExpect(status().isForbidden());

        verify(metricsPort, never()).metricsFor(anyString());
    }

    @Test
    void should_return403_whenAuthHasNoTenantContext() throws Exception {
        UsernamePasswordAuthenticationToken noTenant = new UsernamePasswordAuthenticationToken(
                "admin-user", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));

        mockMvc.perform(get(URL)
                        .header(X_TENANT, TENANT_A)
                        .accept(MediaType.APPLICATION_JSON)
                        .with(authentication(noTenant))
                        .with(csrf()))
                .andExpect(status().isForbidden());

        verify(metricsPort, never()).metricsFor(anyString());
    }

    private static UsernamePasswordAuthenticationToken adminAuth(String tenant) {
        return new UsernamePasswordAuthenticationToken(
                Map.of("tenant", tenant),
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    }
}
