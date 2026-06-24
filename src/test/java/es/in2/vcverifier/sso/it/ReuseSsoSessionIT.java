package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
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
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
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
class ReuseSsoSessionIT {

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


    @BeforeEach
    void setupRegisteredClient() {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("clientA")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://localhost/callback")   // <-- https
                .scope(OidcScopes.OPENID)
                .build();

        when(registeredClientRepository.findByClientId("clientA")).thenReturn(client);
        when(dcqlProfileResolver.resolve(anyString()))
                .thenReturn(new DcqlQuery(List.of()));
    }


    // =========================================================
    // AC-01 HAPPY PATH (ALLOWED)
    // =========================================================
    @Test
    void should_reuse_session_and_redirect_when_allowed() throws Exception {

        String tenant = "tenantA";
        String sessionId = "12345678-SESSION";

        when(tenantSsoConfigPort.getByTenant(tenant))
                .thenReturn(Optional.of(defaultConfig()));

        SsoSession session = mockSession(tenant, Instant.now());

        when(sessionRepositoryPort.findActiveById(any(SsoSessionId.class), eq(tenant)))
                .thenReturn(Optional.of(session));

        mockMvc.perform(get("/oidc/authorize")
                        .cookie(new Cookie("__Secure-sso-" + tenant, sessionId))
                        .param("client_id", "clientA")
                        .param("scope", "openid")
                        .param("state", "xyz")
                        .param("redirect_uri", "https://localhost/callback")
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());

        verify(sessionRepositoryPort, atLeastOnce())
                .findActiveById(any(SsoSessionId.class), eq(tenant));
    }

    // =========================================================
    // AC-02 NO SESSION → LOGIN_REQUIRED
    // =========================================================
    @Test
    void should_redirect_to_login_when_no_session() throws Exception {

        String tenant = "tenantA";

        when(tenantSsoConfigPort.getByTenant(tenant))
                .thenReturn(Optional.of(defaultConfig()));

        when(sessionRepositoryPort.findActiveById(any(SsoSessionId.class), eq(tenant)))
                .thenReturn(Optional.empty());

        mockMvc.perform(get("/oidc/authorize")
                        .cookie(new Cookie("__Secure-sso-" + tenant, "missing"))
                        .param("client_id", "clientA")
                        .param("scope", "openid")
                        .param("state", "xyz")
                        .param("redirect_uri", "http://localhost/callback")
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());
    }

    // =========================================================
    // AC-03 CLIENT NOT ELIGIBLE → INTERACTION_REQUIRED
    // =========================================================
    @Test
    void should_return_interaction_required_when_client_not_eligible() throws Exception {

        String tenant = "tenantA";

        TenantSsoConfig config = new TenantSsoConfig(
                tenant,
                "domain",
                true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
                List.of("other-client")
        );

        when(tenantSsoConfigPort.getByTenant(tenant))
                .thenReturn(Optional.of(config));

        SsoSession session = mockSession(tenant, Instant.now());

        when(sessionRepositoryPort.findActiveById(any(SsoSessionId.class), eq(tenant)))
                .thenReturn(Optional.of(session));

        mockMvc.perform(get("/oidc/authorize")
                        .cookie(new Cookie("__Secure-sso-" + tenant, "123"))
                        .param("client_id", "clientA")
                        .param("scope", "openid")
                        .param("state", "xyz")
                        .param("redirect_uri", "http://localhost/callback")
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());
    }

    // =========================================================
    // EC-01 SESSION EXPIRED
    // =========================================================
    @Test
    void should_fall_back_when_session_expired() throws Exception {

        String tenant = "tenantA";

        when(tenantSsoConfigPort.getByTenant(tenant))
                .thenReturn(Optional.of(defaultConfig()));

        SsoSession expired = mockSession(tenant, Instant.now().minus(Duration.ofHours(10)));

        when(sessionRepositoryPort.findActiveById(any(SsoSessionId.class), eq(tenant)))
                .thenReturn(Optional.of(expired));

        mockMvc.perform(get("/oidc/authorize")
                        .cookie(new Cookie("__Secure-sso-" + tenant, "123"))
                        .param("client_id", "clientA")
                        .param("scope", "openid")
                        .param("state", "xyz")
                        .param("redirect_uri", "http://localhost/callback")
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());
    }

    // =========================================================
    // EC-02 SESSION SUPERSEDED
    // =========================================================
    @Test
    void should_fall_back_when_session_superseded() throws Exception {

        String tenant = "tenantA";

        when(tenantSsoConfigPort.getByTenant(tenant))
                .thenReturn(Optional.of(defaultConfig()));

        SsoSession superseded = mockSession(tenant, Instant.now());

        when(sessionRepositoryPort.findActiveById(any(SsoSessionId.class), eq(tenant)))
                .thenReturn(Optional.of(superseded));

        mockMvc.perform(get("/oidc/authorize")
                        .cookie(new Cookie("__Secure-sso-" + tenant, "123"))
                        .param("client_id", "clientA")
                        .param("scope", "openid")
                        .param("state", "xyz")
                        .param("redirect_uri", "http://localhost/callback")
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());
    }

    // =========================================================
    // ES-01 FAIL-CLOSED (STORE ERROR)
    // =========================================================
    @Test
    void should_fail_closed_when_repository_throws_exception() throws Exception {

        String tenant = "tenantA";

        when(tenantSsoConfigPort.getByTenant(tenant))
                .thenReturn(Optional.of(defaultConfig()));

        when(sessionRepositoryPort.findActiveById(any(SsoSessionId.class), eq(tenant)))
                .thenThrow(new RuntimeException("DB down"));

        mockMvc.perform(get("/oidc/authorize")
                        .cookie(new Cookie("__Secure-sso-" + tenant, "123"))
                        .param("client_id", "clientA")
                        .param("scope", "openid")
                        .param("state", "xyz")
                        .param("redirect_uri", "http://localhost/callback")
                        .param("prompt", "none"))
                .andExpect(status().is3xxRedirection());
    }

    // =========================================================
    // coexistence: prompt=none vs normal flow
    // =========================================================
    @Test
    void should_skip_sso_branch_when_prompt_not_none() throws Exception {

        String tenant = "tenantA";

        mockMvc.perform(get("/oidc/authorize")
                        .cookie(new Cookie("__Secure-sso-" + tenant, "123"))
                        .param("client_id", "clientA")
                        .param("scope", "openid")
                        .param("state", "xyz")
                        .param("redirect_uri", "http://localhost/callback")
                        .param("prompt", "login"))
                .andExpect(status().is3xxRedirection());
    }

    // =========================================================
    // helpers
    // =========================================================

    private TenantSsoConfig defaultConfig() {
        return new TenantSsoConfig(
                "tenantA",
                "domain",
                true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
                List.of("clientA")
        );
    }

    private SsoSession mockSession(String tenant, Instant now) {

        SsoSession session = SsoSession.establish(
                tenant,
                "hash",
                Duration.ofMinutes(30)
        );

        // Ajuste controlado del tiempo para escenarios de test
        session.setLastUsedAt(now);

        return session;
    }
}