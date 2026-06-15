package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Testcontainers
@SpringBootTest(properties = {
        "clients.config.path=test-fixtures/clients.yaml",
        "spring.autoconfigure.exclude=es.in2.vcverifier.oauth2.infrastructure.config.AuthorizationServerConfig"
})
@AutoConfigureMockMvc
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
    RegisteredClientRepository registeredClientRepository;

    @MockitoBean
    SsoAuditPort auditPort;



    @BeforeEach
    void clean() {
        jdbcTemplate.update("DELETE FROM sso_session");
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

        mockMvc.perform(post("/sso/session")
                        .principal(() -> "tenant-a")
                        .contentType("application/json")
                        .content(validVp()))
                .andExpect(status().isOk())
                .andExpect(header().exists("Set-Cookie"))
                .andExpect(cookie().exists("SSO_SESSION"));

        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE tenant='tenant-a'",
                Integer.class
        );

        assertThat(count).isEqualTo(1);

        verify(auditPort, atLeastOnce())
                .publish(argThat(e -> e instanceof SsoAuditEvent));
    }

    // =========================================================
    // AC-04: tenant legacy sso.enabled=false => no cookie
    // =========================================================
    @Test
    void legacyTenant_doesNotSetCookie() throws Exception {

        mockMvc.perform(post("/sso/session")
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
        mockMvc.perform(post("/sso/session")
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
        mockMvc.perform(post("/sso/session")
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

        mockMvc.perform(post("/sso/session")
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