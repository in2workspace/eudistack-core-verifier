package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.config.TimeConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.sso.infrastructure.web.SsoSessionAuthenticationSuccessHandler;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.rnorth.ducttape.circuitbreakers.StateStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@Import(TimeConfig.class)
class EstablishSsoSessionIT {

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
    }

    @Autowired
    MockMvc mockMvc;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @MockitoBean
    ClientRegistryProvider clientRegistryProvider;
    @MockitoBean RegisteredClientRepository registeredClientRepository;
    @MockitoBean
    ClientLoaderConfig clientLoaderConfig;
    @MockitoBean
    SsoSessionAuthenticationSuccessHandler handler;

    @MockitoBean
    private SsoSessionRepositoryPort repository;
    @MockitoBean private SsoAuditPort auditPort;
    @MockitoBean private TenantSsoConfigPort tenantSsoConfigPort;
    @MockitoBean private HashingService hashingService;
    @MockitoBean private Clock clock;
    @MockitoBean
    StateStore stateStore;
    @MockitoBean
    CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;

    @MockitoBean
    AuthorizationResponseProcessorService authorizationResponseProcessorService;


    @BeforeEach
    void clean() {
//        jdbcTemplate.update("CREATE TABLE sso_session IF NOT EXISTS");
//        jdbcTemplate.update("DELETE FROM sso_session");
        reset(auditPort);
    }

    // =========================================================
    // Helper VP válido/inválido
    // =========================================================
    private String validVp() {
        return """
        {
          "vp": "valid-vp",
          "tenant": "tenant-a"
        }
        """;
    }

    private String invalidVp() {
        return """
        {
          "vp": "invalid-vp",
          "tenant": "tenant-a"
        }
        """;
    }

    // =========================================================
    // AC-01 + AC-03: happy path
    // =========================================================
    @Test
    void establishSession_createsRow_and_setsCookie() throws Exception {

        OAuth2AuthorizationRequest request =
                OAuth2AuthorizationRequest.authorizationCode()
                        .authorizationUri("http://test")
                        .clientId("client-id")
                        .redirectUri("http://redirect")
                        .state("test-state")
                        .additionalParameters(Map.of(
                                "expiration", Instant.now().plusSeconds(60).getEpochSecond(),
                                "nonce", "nonce"
                        ))
                        .build();

        when(cacheStoreForOAuth2AuthorizationRequest.get("test-state"))
                .thenReturn(request);

        doNothing()
                .when(authorizationResponseProcessorService)
                .handleAuthResponse(
                        anyString(),
                        anyString()
                );

        mockMvc.perform(post("/oid4vp/auth-response")
                        .principal(() -> "tenant-a")
                        .param("state", "test-state")
                        // puedes dejarlo simple, ya no se valida JWT real
                        .param("vp_token", "dummy-vp-token")
                        .contentType("application/json")
                        .content("""
                        {
                          "vp": "dummy-vp-token",
                          "tenant": "tenant-a"
                        }
                    """))
                .andExpect(status().isOk())
                .andExpect(header().exists("Set-Cookie"))
                .andExpect(cookie().exists("__Secure-sso-tenant-a"));

        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE tenant='tenant-a'",
                Integer.class
        );

        assertThat(count).isEqualTo(1);

        verify(auditPort, atLeastOnce())
                .publish(any(SsoAuditEvent.class));
    }

    // =========================================================
    // AC-04: tenant legacy sso.enabled=false => no cookie
    // =========================================================
    @Test
    void legacyTenant_doesNotSetCookie() throws Exception {

        mockMvc.perform(post("/oid4vp/auth-response")
                        .principal(() -> "legacy-tenant")
                        .contentType("application/json")
                        .content(validVp()))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Set-Cookie"));

        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE tenant='legacy-tenant'",
                Integer.class
        );

        assertThat(count).isEqualTo(1);
    }

    // =========================================================
    // EC-01: re-establish -> new session + supersede previous
    // =========================================================
    @Test
    void reestablish_supersedes_previous_session() throws Exception {

        // primera sesión
        mockMvc.perform(post("/oid4vp/auth-response")
                        .principal(() -> "tenant-a")
                        .contentType("application/json")
                        .content(validVp()))
                .andExpect(status().isOk());

        Integer firstCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE tenant='tenant-a'",
                Integer.class
        );

        assertThat(firstCount).isEqualTo(1);

        // segunda sesión (re-establish)
        mockMvc.perform(post("/oid4vp/auth-response")
                        .principal(() -> "tenant-a")
                        .contentType("application/json")
                        .content(validVp()))
                .andExpect(status().isOk())
                .andExpect(header().exists("Set-Cookie"));

        Integer total = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE tenant='tenant-a'",
                Integer.class
        );

        assertThat(total).isEqualTo(2);

        Integer activeCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE tenant='tenant-a' AND state='ACTIVE'",
                Integer.class
        );

        assertThat(activeCount).isEqualTo(1);
    }

    // =========================================================
    // ES-01: VP inválida -> no session + access_denied + sso_establish_failed
    // =========================================================
    @Test
    void invalidVp_returnsAccessDenied_and_noSession() throws Exception {

        mockMvc.perform(post("/oid4vp/auth-response")
                        .principal(() -> "tenant-a")
                        .contentType("application/json")
                        .content(invalidVp()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("access_denied"))
                .andExpect(jsonPath("$.code").value("sso_establish_failed"));

        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE tenant='tenant-a'",
                Integer.class
        );

        assertThat(count).isEqualTo(0);

        verify(auditPort, atLeastOnce())
                .publish(argThat(e -> e instanceof SsoAuditEvent));
    }
}