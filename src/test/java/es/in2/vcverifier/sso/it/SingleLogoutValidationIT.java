package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.util.Constants;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import jakarta.servlet.http.Cookie;
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
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_LOGIN_PAGE_URI;

/**
 * IT — US-06 ES-01: la validación estándar de {@code id_token_hint}/
 * {@code post_logout_redirect_uri} (Spring AS {@code OidcLogoutAuthenticationProvider}/
 * {@code OidcLogoutAuthenticationConverter}) rechaza la solicitud ANTES de que
 * {@link es.in2.vcverifier.sso.infrastructure.web.SsoSessionLogoutHandler} se invoque:
 * ninguna invalidación, ningún dispatch. {@code SsoSessionLogoutFailureHandler} emite
 * {@code sso_logout_rejected} y, cuando el cliente resuelto vía {@code client_id} tiene
 * {@code loginPageUri} configurada, redirige ahí con {@code ?error=session_expired}; si no,
 * intenta el {@code post_logout_redirect_uri} de la request cuando coincide con uno ya
 * registrado para ese cliente; en caso contrario delega en
 * {@code OAuth2ErrorAuthenticationFailureHandler} (400 Bad Request estándar, verificado
 * por bytecode — mismo rigor que Task 8/14).
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureMockMvc
class SingleLogoutValidationIT {

    private static final String TENANT = "tenant-a";
    private static final String CLIENT_ID = "client-es01";
    private static final String POST_LOGOUT_REDIRECT_URI = "https://client-es01.example.com/logged-out";

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

        client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client-es01.example.com/callback")
                .postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI)
                .scope(OidcScopes.OPENID)
                .build();
        when(registeredClientRepository.findById(client.getId())).thenReturn(client);
    }

    // =========================================================
    // ES-01: id_token_hint ausente — el converter rechaza antes del provider.
    // =========================================================
    @Test
    void singleLogout_rejectsRequest_whenIdTokenHintMissing() throws Exception {
        String sessionId = insertActiveSession();

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", CLIENT_ID))
                .andExpect(status().isBadRequest());

        assertThat(sessionState(sessionId)).isEqualTo("ACTIVE");
        verify(auditPort, timeout(2000)).publish(argThatRejected());
    }

    // =========================================================
    // ES-01: id_token_hint desconocido (no resuelto por OAuth2AuthorizationService) — invalid_token.
    // =========================================================
    @Test
    void singleLogout_rejectsRequest_whenIdTokenHintIsUnknown() throws Exception {
        String sessionId = insertActiveSession();

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", "not-a-known-token")
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", CLIENT_ID))
                .andExpect(status().isBadRequest());

        assertThat(sessionState(sessionId)).isEqualTo("ACTIVE");
        verify(auditPort, timeout(2000)).publish(argThatRejected());
    }

    // =========================================================
    // ES-01: post_logout_redirect_uri no registrado para el cliente — invalid_request.
    // =========================================================
    @Test
    void singleLogout_rejectsRequest_whenPostLogoutRedirectUriNotRegistered() throws Exception {
        String sessionId = insertActiveSession();
        String idTokenHint = saveIdTokenAuthorization("subject-es01");

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", "https://not-registered.example.com/logged-out")
                        .param("client_id", CLIENT_ID))
                .andExpect(status().isBadRequest());

        assertThat(sessionState(sessionId)).isEqualTo("ACTIVE");
        verify(auditPort, timeout(2000)).publish(argThatRejected());
    }

    // =========================================================
    // ES-01: cliente con loginPageUri configurada — redirige con ?error=session_expired
    // en vez de exponer el JSON crudo del error estándar.
    // =========================================================
    @Test
    void singleLogout_redirectsToLoginPage_whenClientHasLoginPageConfigured() throws Exception {
        String sessionId = insertActiveSession();
        String idTokenHint = saveIdTokenAuthorization("subject-es01");
        String loginPageUri = "https://client-es01.example.com/login";

        RegisteredClient clientWithLoginPage = RegisteredClient.from(client)
                .clientSettings(ClientSettings.builder()
                        .setting(CLIENT_SETTING_LOGIN_PAGE_URI, loginPageUri)
                        .build())
                .build();
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(clientWithLoginPage);

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", idTokenHint)
                        .param("post_logout_redirect_uri", "https://not-registered.example.com/logged-out")
                        .param("client_id", CLIENT_ID))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(loginPageUri + "?error=session_expired"));

        assertThat(sessionState(sessionId)).isEqualTo("ACTIVE");
        verify(auditPort, timeout(2000)).publish(argThatRejected());
    }

    // =========================================================
    // ES-01: cliente SIN loginPageUri (p. ej. el Issuer UI, que delega su login en el
    // mfe-login compartido) pero con post_logout_redirect_uri ya registrado — redirige ahí
    // con ?error=session_expired en vez de exponer el JSON crudo. Cubre el caso que
    // loginPageUri por sí solo no puede resolver sin romper el login normal de ese cliente.
    // =========================================================
    @Test
    void singleLogout_redirectsToRegisteredPostLogoutRedirectUri_whenClientHasNoLoginPage() throws Exception {
        String sessionId = insertActiveSession();
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(client);

        mockMvc.perform(post("/oidc/logout")
                        .header(Constants.X_TENANT_HEADER, TENANT)
                        .cookie(new Cookie("__Secure-sso-" + TENANT, sessionId))
                        .param("id_token_hint", "not-a-known-token")
                        .param("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI)
                        .param("client_id", CLIENT_ID))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(POST_LOGOUT_REDIRECT_URI + "?error=session_expired"));

        assertThat(sessionState(sessionId)).isEqualTo("ACTIVE");
        verify(auditPort, timeout(2000)).publish(argThatRejected());
    }

    // =========================================================
    // HELPERS
    // =========================================================

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

    private String insertActiveSession() {
        String id = UUID.randomUUID().toString();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbcTemplate.update("""
                INSERT INTO sso_session
                    (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
                """,
                id, TENANT, "holder-" + id,
                now, now.plusHours(1), now);
        return id;
    }

    private String sessionState(String sessionId) {
        return jdbcTemplate.queryForObject(
                "SELECT state FROM sso_session WHERE id = ?", String.class, sessionId);
    }

    private es.in2.vcverifier.sso.domain.model.SsoAuditEvent argThatRejected() {
        return org.mockito.ArgumentMatchers.argThat(event ->
                event.getEventType() == es.in2.vcverifier.sso.domain.model.SsoAuditEvent.EventType.SSO_LOGOUT_REJECTED);
    }
}
