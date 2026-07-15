package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.oauth2.infrastructure.filter.CustomErrorResponseHandler;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.exception.SsoSessionRepositoryException;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.sso.infrastructure.persistence.SsoSessionJdbcRepository;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
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
class SsoSessionJdbcRepositoryRevokeIT {

    private static final String TENANT_A = "tenant-a";
    private static final String TENANT_B = "tenant-b";
    private static final String BLOCK_DELETE_TRIGGER = "sso_session_block_delete";

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

    @Autowired
    private SsoSessionJdbcRepository sessionRepository;

    @MockitoBean private TenantSsoConfigPort tenantSsoConfigPort;
    @MockitoBean private SsoAuditPort auditPort;
    @MockitoBean private SsoCatalogRepositoryPort ssoCatalogRepositoryPort;
    @MockitoBean private ClientLoaderConfig clientLoaderConfig;
    @MockitoBean private RegisteredClientRepository registeredClientRepository;
    @MockitoBean private DcqlProfileResolver dcqlProfileResolver;
    @MockitoBean private CustomErrorResponseHandler customErrorResponseHandler;
    @MockitoBean private ClientRegistryProvider clientRegistryProvider;

    @BeforeEach
    void setUp() {
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS sso_session (
                    id            TEXT        PRIMARY KEY,
                    tenant        TEXT        NOT NULL,
                    holder_hash   TEXT        NOT NULL,
                    established_at TIMESTAMPTZ NOT NULL,
                    expires_at    TIMESTAMPTZ NOT NULL,
                    last_used_at  TIMESTAMPTZ NOT NULL,
                    state         VARCHAR(32) NOT NULL
                )
                """);
        dropBlockDeleteTrigger();
        jdbcTemplate.execute("DELETE FROM sso_session");
    }

    @Test
    void shouldReturnRemovedRowCount() {
        seedSession(TENANT_A, "h1", "ACTIVE");
        seedSession(TENANT_A, "h2", "ACTIVE");
        seedSession(TENANT_A, "h3", "SUPERSEDED");

        int revoked = sessionRepository.revokeAllByTenant(TENANT_A);

        assertThat(revoked).isEqualTo(3);
        assertThat(countByTenant(TENANT_A)).isZero();
    }

    @Test
    void shouldReturnZero_whenTenantHasNoSessions() {
        seedSession(TENANT_B, "h1", "ACTIVE");

        int revoked = sessionRepository.revokeAllByTenant("empty-tenant");

        assertThat(revoked).isZero();
        assertThat(countByTenant(TENANT_B)).isEqualTo(1);
    }

    @Test
    void shouldRevokeOnlyTargetTenant_leavingOthersIntact() {
        seedSession(TENANT_A, "h1", "ACTIVE");
        seedSession(TENANT_A, "h2", "ACTIVE");
        seedSession(TENANT_B, "h1", "ACTIVE");
        seedSession(TENANT_B, "h2", "ACTIVE");
        seedSession(TENANT_B, "h3", "ACTIVE");

        int revoked = sessionRepository.revokeAllByTenant(TENANT_A);

        assertThat(revoked).isEqualTo(2);
        assertThat(countByTenant(TENANT_A)).isZero();
        assertThat(countByTenant(TENANT_B)).isEqualTo(3);
    }

    @Test
    void shouldRollbackAndPreserveAllRows_whenDeleteFails() {
        seedSession(TENANT_A, "h1", "ACTIVE");
        seedSession(TENANT_A, "h2", "ACTIVE");
        seedSession(TENANT_A, "h3", "ACTIVE");

        installBlockDeleteTrigger();
        try {
            assertThatThrownBy(() -> sessionRepository.revokeAllByTenant(TENANT_A))
                    .isInstanceOf(SsoSessionRepositoryException.class);

            assertThat(countByTenant(TENANT_A)).isEqualTo(3);
        } finally {
            dropBlockDeleteTrigger();
        }
    }

    // --- helpers ---

    private void seedSession(String tenant, String holderHash, String state) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbcTemplate.update("""
                INSERT INTO sso_session
                    (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                UUID.randomUUID().toString(), tenant, holderHash,
                now, now.plusHours(1), now, state);
    }

    private int countByTenant(String tenant) {
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE tenant = ?", Integer.class, tenant);
        return count == null ? 0 : count;
    }

    private void installBlockDeleteTrigger() {
        jdbcTemplate.execute("""
                CREATE OR REPLACE FUNCTION sso_session_fail_on_delete() RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'delete blocked for atomicity test';
                END;
                $$ LANGUAGE plpgsql
                """);
        jdbcTemplate.execute(
                "CREATE TRIGGER " + BLOCK_DELETE_TRIGGER
                        + " BEFORE DELETE ON sso_session"
                        + " FOR EACH ROW EXECUTE FUNCTION sso_session_fail_on_delete()");
    }

    private void dropBlockDeleteTrigger() {
        jdbcTemplate.execute(
                "DROP TRIGGER IF EXISTS " + BLOCK_DELETE_TRIGGER + " ON sso_session");
    }
}
