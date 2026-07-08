package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.util.Constants;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IT — US-06 AC-05 / R-1: regresión crítica del enganche AD-1 sobre el RP-Initiated Logout
 * estándar de Spring Authorization Server. Un tenant sin sesión SSO activa (cookie ausente —
 * el caso real de {@code sso.enabled=false}, que nunca llega a establecer la cookie, ver
 * {@code EstablishSsoSessionWorkflow}) o con una cookie que ya no referencia una sesión real en
 * BD (expirada/purgada) debe completar el logout OIDC 1.0 estándar exactamente igual que antes
 * de esta Story: sin error expuesto al RP, sin notificaciones Back-Channel Logout.
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureMockMvc
class SingleLogoutLegacyIT {

    private static final String TENANT = "tenant-legacy";
    private static final String CLIENT_ID = "legacy-client";
    private static final String POST_LOGOUT_REDIRECT_URI = "https://legacy-client.example.com/logged-out";

    @Container
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("vcverifier")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.flyway.url", postgres::getJdbcUrl);
        registry.add("spring.flyway.user", postgres::getUsername);
        registry.add("spring.flyway.password", postgres::getPassword);
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private OAuth2AuthorizationService authorizationService;

    @MockitoBean private RegisteredClientRepository registeredClientRepository;
    @MockitoBean private TenantSsoConfigPort tenantSsoConfigPort;
    @MockitoBean private SsoAuditPort auditPort;
    @MockitoBean private ClientLoaderConfig clientLoaderConfig;
    @MockitoBean private ClientRegistryProvider clientRegistryProvider;
    @MockitoBean private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;

    private RegisteredClient client;

    @BeforeEach
    void setUp() {
        jdbcTemplate.update("DELETE FROM sso_session_client");
        jdbcTemplate.update("DELETE FROM sso_session");

        // sso.enabled=false: representa el tenant legacy. No se stubbea porque, en el flujo
        // real, un tenant sin SSO nunca establece la cookie __Secure-sso-<tenant> en primer
        // lugar (EstablishSsoSessionWorkflow corta antes) — el propio handler AD-1 nunca
        // necesita consultar este puerto si no hay cookie (ver AC-05 en SsoSessionLogoutHandler).
        client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://legacy-client.example.com/callback")
                .postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI)
                .scope(OidcScopes.OPENID)
                .build();
        when(registeredClientRepository.findById(client.getId())).thenReturn(client);
    }

    // =========================================================
    // AC-05 / R-1: sin cookie SSO (tenant legacy real) — no-op total, logout estándar intacto.
    // =========================================================
    @Test
    void singleLogoutLegacy_withoutSsoCookie_completesStandardOidcLogout() throws Exception {
        String idTokenHint = saveIdTokenAuthorization("subject-legacy-1");

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", CLIENT_ID))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(POST_LOGOUT_REDIRECT_URI));

        // AC-05: el bloque SSO es un no-op por construcción (sin cookie) — cero interacción
        // con el puerto de auditoría SSO, ninguna llamada de invalidación/dispatch.
        verifyNoInteractions(auditPort);
    }

    // =========================================================
    // AC-05 / R-1: cookie SSO presente pero sin fila real en BD (sesión purgada/expirada) —
    // el logout estándar sigue completando sin error expuesto al RP.
    // =========================================================
    @Test
    void singleLogoutLegacy_withStaleCookieAndNoSessionInDb_stillCompletesStandardLogout() throws Exception {
        String idTokenHint = saveIdTokenAuthorization("subject-legacy-2");
        String staleSessionId = UUID.randomUUID().toString(); // no existe en sso_session

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new jakarta.servlet.http.Cookie("__Secure-sso-" + TENANT, staleSessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", CLIENT_ID))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(POST_LOGOUT_REDIRECT_URI));

        Integer sessionCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE id = ?", Integer.class, staleSessionId);
        assertThat(sessionCount).isZero();
    }

    private String saveIdTokenAuthorization(String subject) {
        String tokenValue = UUID.randomUUID().toString();
        Instant now = Instant.now();

        OidcIdToken idToken = OidcIdToken.withTokenValue(tokenValue)
                .subject(subject)
                .audience(List.of(client.getClientId()))
                .issuer("https://" + TENANT + ".example.com")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .build();

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName(subject)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(idToken)
                .build();

        authorizationService.save(authorization);
        return tokenValue;
    }
}
