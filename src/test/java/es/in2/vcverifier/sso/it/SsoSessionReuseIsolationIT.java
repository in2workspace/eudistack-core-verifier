package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.domain.model.dcql.DcqlQuery;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
class SsoSessionReuseIsolationIT {

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

    @MockitoBean
    private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;

    @BeforeEach
    void setup() {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-b")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://localhost/callback")
                .scope(OidcScopes.OPENID)
                .build();

        when(registeredClientRepository.findByClientId("client-b")).thenReturn(client);
        when(dcqlProfileResolver.resolve(anyString())).thenReturn(new DcqlQuery(List.of()));
    }

    // =========================================================
    // AC-04: CROSS-TENANT ISOLATION
    // =========================================================
    @Test
    void should_return_login_required_when_cookie_from_other_tenant_is_used() throws Exception {

        String tenantA = "tenant-a";
        String tenantB = "tenant-b";

        // config para tenant B (request actual)
        when(tenantSsoConfigPort.getByTenant(tenantB))
                .thenReturn(Optional.of(config(tenantB)));

        // Aunque exista sesión en tenant A, NO debe consultarse desde tenant B
        when(sessionRepositoryPort.findActiveById(any(SsoSessionId.class), eq(tenantB)))
                .thenReturn(Optional.empty());

        mockMvc.perform(get("/oidc/authorize")
                        // cookie generada en tenant A — no sirve para tenant B
                        .cookie(new Cookie("__Secure-sso-" + tenantA, "SESSION-123"))
                        // tenant B explícito vía X-Tenant: TenantDomainFilter lo resuelve
                        // correctamente y backendConfig.getUrl() devuelve https://localhost
                        // (sin Host override), permitiendo el redirect de error al client.
                        .header("X-Tenant", tenantB)
                        .header("X-Forwarded-Proto", "https")
                        .param("client_id", "client-b")
                        .param("scope", "openid")
                        .param("state", "xyz")
                        .param("redirect_uri", "https://localhost/callback")
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        // =========================================================
        // ASSERTIÓN CRÍTICA DE AISLAMIENTO
        // =========================================================

        // nunca debe intentar resolver sesión en tenant A desde contexto B
        verify(sessionRepositoryPort, never())
                .findActiveById(any(SsoSessionId.class), eq(tenantA));
    }

    // =========================================================
    // helper
    // =========================================================

    private TenantSsoConfig config(String tenant) {
        return new TenantSsoConfig(
                tenant,
                "domain",
                true,
                new TenantSsoConfig.SsoTtlConfig(
                        Duration.ofHours(1),
                        Duration.ofMinutes(10)
                ),
                List.of("client-b")
        );
    }
}