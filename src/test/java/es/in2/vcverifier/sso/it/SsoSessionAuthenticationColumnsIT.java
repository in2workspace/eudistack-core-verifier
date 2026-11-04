package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.oauth2.infrastructure.filter.CustomErrorResponseHandler;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(properties = {
        "verifier.backend.url=https://localhost",
        "verifier.frontend.portalUrl=https://localhost",
        "spring.security.oauth2.authorizationserver.endpoint.authorization-uri-validation=false"
})
@Testcontainers
@ActiveProfiles("test")
class SsoSessionAuthenticationColumnsIT {

    @Container
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("vcverifier")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",      postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.flyway.url",          postgres::getJdbcUrl);
        registry.add("spring.flyway.user",         postgres::getUsername);
        registry.add("spring.flyway.password",     postgres::getPassword);
    }

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @MockitoBean private TenantSsoConfigPort tenantSsoConfigPort;
    @MockitoBean private SsoAuditPort auditPort;
    @MockitoBean private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;
    @MockitoBean private ClientLoaderConfig clientLoaderConfig;
    @MockitoBean private RegisteredClientRepository registeredClientRepository;
    @MockitoBean private DcqlProfileResolver dcqlProfileResolver;
    @MockitoBean private CustomErrorResponseHandler customErrorResponseHandler;
    @MockitoBean private ClientRegistryProvider clientRegistryProvider;

    @Test
    void sessionWithoutAuthenticationColumns_isAWalletSessionWithoutLevel() {
        String id = insertSession();

        Map<String, Object> row = jdbcTemplate.queryForMap(
                "SELECT auth_method, acr, amr, certificate_not_after FROM sso_session WHERE id = ?", id);

        assertThat(row.get("auth_method")).isEqualTo("wallet");
        assertThat(row.get("acr")).isNull();
        assertThat(row.get("amr")).isNull();
        assertThat(row.get("certificate_not_after")).isNull();
    }

    @Test
    void certificateSession_keepsItsMethodLevelAmrAndEndOfValidity() {
        String id = insertSession();
        OffsetDateTime notAfter = OffsetDateTime.of(2028, 5, 1, 0, 0, 0, 0, ZoneOffset.UTC);

        jdbcTemplate.update("""
                UPDATE sso_session
                SET auth_method = 'x509', acr = ?, amr = ARRAY['hwk'], certificate_not_after = ?
                WHERE id = ?
                """, "http://eidas.europa.eu/LoA/high", notAfter, id);

        Map<String, Object> row = jdbcTemplate.queryForMap(
                "SELECT auth_method, acr, array_to_string(amr, ' ') AS amr, certificate_not_after FROM sso_session WHERE id = ?", id);
        assertThat(row.get("auth_method")).isEqualTo("x509");
        assertThat(row.get("acr")).isEqualTo("http://eidas.europa.eu/LoA/high");
        assertThat(row.get("amr")).isEqualTo("hwk");
        assertThat(jdbcTemplate.queryForObject(
                "SELECT certificate_not_after FROM sso_session WHERE id = ?", OffsetDateTime.class, id))
                .isEqualTo(notAfter);
    }

    @Test
    void unknownAuthMethod_isRejected() {
        String id = insertSession();

        assertThatThrownBy(() -> jdbcTemplate.update(
                "UPDATE sso_session SET auth_method = 'password' WHERE id = ?", id))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    private String insertSession() {
        String id = UUID.randomUUID().toString();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbcTemplate.update("""
                INSERT INTO sso_session (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, 'tenant-a', ?, ?, ?, ?, 'TERMINATED')
                """, id, "holder-" + id, now, now.plusHours(8), now);
        return id;
    }
}
