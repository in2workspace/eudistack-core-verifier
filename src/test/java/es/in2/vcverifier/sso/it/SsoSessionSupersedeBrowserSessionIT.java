package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.oauth2.infrastructure.filter.CustomErrorResponseHandler;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import es.in2.vcverifier.sso.infrastructure.persistence.SsoSessionJdbcRepository;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
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

@SpringBootTest(properties = {
        "verifier.backend.url=https://localhost",
        "verifier.frontend.portalUrl=https://localhost",
        "spring.security.oauth2.authorizationserver.endpoint.authorization-uri-validation=false"
})
@Testcontainers
@ActiveProfiles("test")
class SsoSessionSupersedeBrowserSessionIT {

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

    @Test
    void supersedeActive_supersedesTheBrowserSessionOfAnotherHolder() {
        String holderASession = insertActive("tenant-a", "holder-a");
        String holderBSession = insertActive("tenant-a", "holder-b");
        String holderCSession = insertActive("tenant-a", "holder-c");

        sessionRepository.supersedeActive("tenant-a", "holder-b", holderASession);

        assertThat(state(holderASession)).isEqualTo("SUPERSEDED");
        assertThat(state(holderBSession)).isEqualTo("SUPERSEDED");
        assertThat(state(holderCSession)).isEqualTo("ACTIVE");
    }

    @Test
    void supersedeActive_neverSupersedesASessionOfAnotherTenant() {
        String otherTenantSession = insertActive("tenant-b", "holder-a");

        sessionRepository.supersedeActive("tenant-a", "holder-b", otherTenantSession);

        assertThat(state(otherTenantSession)).isEqualTo("ACTIVE");
    }

    @Test
    void supersedeActive_withoutBrowserSession_supersedesOnlyTheHolder() {
        String holderASession = insertActive("tenant-a", "holder-a2");
        String holderBSession = insertActive("tenant-a", "holder-b2");

        sessionRepository.supersedeActive("tenant-a", "holder-b2", null);

        assertThat(state(holderASession)).isEqualTo("ACTIVE");
        assertThat(state(holderBSession)).isEqualTo("SUPERSEDED");
    }

    private String insertActive(String tenant, String holderHash) {
        String id = UUID.randomUUID().toString();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        jdbcTemplate.update("""
                INSERT INTO sso_session (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
                """, id, tenant, holderHash, now, now.plusHours(8), now);
        return id;
    }

    private String state(String id) {
        return jdbcTemplate.queryForObject("SELECT state FROM sso_session WHERE id = ?", String.class, id);
    }
}
