package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.config.TimeConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
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

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@Import(TimeConfig.class)
class SsoSessionReestablishSupersedesPreviousSessionIT {

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

    @Autowired MockMvc mockMvc;
    @Autowired JdbcTemplate jdbcTemplate;

    @MockitoBean ClientRegistryProvider clientRegistryProvider;
    @MockitoBean RegisteredClientRepository registeredClientRepository;
    @MockitoBean
    ClientLoaderConfig clientLoaderConfig;

    @MockitoBean SsoAuditPort auditPort;
    @MockitoBean TenantSsoConfigPort tenantSsoConfigPort;
    @MockitoBean HashingService hashingService;
    @MockitoBean
    StateStore stateStore;
    @MockitoBean
    CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    @MockitoBean AuthorizationResponseProcessorService authorizationResponseProcessorService;
    @Autowired SsoSessionRepositoryPort sessionRepositoryPort;

    @BeforeEach
    void clean() {
        jdbcTemplate.execute("""
        CREATE TABLE IF NOT EXISTS sso_session (
            id TEXT PRIMARY KEY,
            tenant TEXT NOT NULL,
            holder_hash TEXT NOT NULL,
            established_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            state VARCHAR(32) NOT NULL
        )
        """);

        jdbcTemplate.execute("DELETE FROM sso_session");
        reset(auditPort);
    }

    @Test
    void reestablish_supersedes_previous_session() throws Exception {

        // -----------------------------
        // 1. TENANT CONFIG OBLIGATORIA
        // -----------------------------
        when(tenantSsoConfigPort.getByTenant(any()))
                .thenReturn(Optional.of(
                        new es.in2.vcverifier.shared.domain.model.TenantSsoConfig(
                                "tenant-a",
                                "example.com",
                                true,
                                new es.in2.vcverifier.shared.domain.model.TenantSsoConfig.SsoTtlConfig(
                                        Duration.ofHours(8),
                                        Duration.ofHours(1)
                                )
                        )
                ));

        // -----------------------------
        // 2. HASHING
        // -----------------------------
        when(hashingService.sha256(any()))
                .thenReturn("hashed-user");

        // -----------------------------
        // 3. PRIMERA PETICIÓN
        // -----------------------------
        mockMvc.perform(post("/oid4vp/auth-response")
                        .requestAttr(TenantDomainFilter.TENANT_ATTRIBUTE, "tenant-a")
                        .param("state", "test-state")
                        .param("vp_token", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0LWhvbGRlciJ9.fakesig"))
                .andExpect(status().is3xxRedirection());

        Integer firstCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sso_session WHERE tenant='tenant-a'",
                Integer.class
        );

        assertThat(firstCount).isEqualTo(1);

        // -----------------------------
        // 4. SEGUNDA PETICIÓN
        // -----------------------------
        mockMvc.perform(post("/oid4vp/auth-response")
                        .requestAttr(TenantDomainFilter.TENANT_ATTRIBUTE, "tenant-a")
                        .param("state", "test-state-2")
                        .param("vp_token", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0LWhvbGRlciJ9.fakesig"))
                .andExpect(status().is3xxRedirection())
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
}