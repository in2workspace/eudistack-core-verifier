package es.in2.vcverifier.oauth2.it;

import es.in2.vcverifier.oauth2.application.workflow.ClientCredentialsValidationWorkflow;
import es.in2.vcverifier.oauth2.application.workflow.TokenGenerationWorkflow;
import es.in2.vcverifier.oauth2.domain.exception.InvalidProofOfPossessionException;
import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.infrastructure.audit.RejectionThrottle;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static es.in2.vcverifier.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The audit trail of the Verifier end to end, with the publisher of the starter on and a real PostgreSQL: a
 * request to the real {@code /oidc/token} goes through the real security chain, the real audit context filter and
 * the real outbox (DT-002 §2.3).
 *
 * <p>It checks what the unit tests, which run against a recording double, cannot see:
 * <ul>
 *   <li>the {@code SystemAuthenticated} of a refused machine is a span {@code audit.outbox.stage} carrying its
 *       {@code audit.event_type} (RQ-23) and a row of {@code public.audit_outbox}, in the tenant of the request
 *       and with the Verifier as actor, never the {@code client_id} the caller wrote;</li>
 *   <li>a request leaves one row of its type (R-3), and a stream of refusals of one client leaves only the few the
 *       limit allows: the endpoint needs no authentication, so it cannot fill the outbox.</li>
 * </ul>
 * The workflow that validates the attestation is mocked, as in {@code M2MRejectionIT}: what is under test is the
 * layer above it.
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureMockMvc
@TestPropertySource(properties = {"auditoria.publisher.enabled=true", "auditoria.dispatcher.enabled=false"})
class AuditOutboxFlowIT {

    private static final String TENANT = "dome";
    private static final String ASSERTION = "header.payload.signature";
    private static final String SYSTEM_AUTHENTICATED = "SystemAuthenticated";

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

    /** Records the {@code audit.event_type} of every stage span that finished. */
    static final class StageSpans implements ObservationHandler<Observation.Context> {

        private final List<String> eventTypes = new CopyOnWriteArrayList<>();

        @Override
        public boolean supportsContext(Observation.Context context) {
            return "audit.outbox.stage".equals(context.getName());
        }

        @Override
        public void onStop(Observation.Context context) {
            var eventType = context.getLowCardinalityKeyValue("audit.event_type");
            eventTypes.add(eventType == null ? "<none>" : eventType.getValue());
        }

        List<String> eventTypes() {
            return List.copyOf(eventTypes);
        }

        void clear() {
            eventTypes.clear();
        }
    }

    @TestConfiguration
    static class SpanRecording {

        @Bean
        StageSpans stageSpans() {
            return new StageSpans();
        }
    }

    @Autowired MockMvc mockMvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired StageSpans stageSpans;

    @MockitoBean ClientRegistryProvider clientRegistryProvider;
    @MockitoBean ClientLoaderConfig clientLoaderConfig;
    @MockitoBean RegisteredClientRepository registeredClientRepository;
    @MockitoBean ClientCredentialsValidationWorkflow clientCredentialsValidationWorkflow;
    @MockitoBean TokenGenerationWorkflow tokenGenerationWorkflow;

    @BeforeEach
    void cleanOutboxAndSpans() {
        jdbc.update("DELETE FROM public.audit_outbox");
        stageSpans.clear();
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(anyString(), anyString()))
                .thenThrow(new InvalidProofOfPossessionException("Invalid JWT claims from assertion"));
    }

    @Test
    void refusedMachine_stagesOneSystemAuthenticatedDenied_asAStageSpanInTheTenantOfTheRequest() throws Exception {
        // When
        tokenRequestOf("did:key:z6MkOneRefusedMachine").andExpect(status().isBadRequest());

        // Then: a row and a span of the type, once
        assertThat(rowsOf(SYSTEM_AUTHENTICATED)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM public.audit_outbox", Integer.class)).isEqualTo(1);
        assertThat(stageSpans.eventTypes()).containsExactly(SYSTEM_AUTHENTICATED);
        assertThat(jdbc.queryForObject("SELECT tenant FROM public.audit_outbox", String.class)).isEqualTo(TENANT);
        assertThat(jdbc.queryForObject("SELECT payload->>'result' FROM public.audit_outbox", String.class))
                .isEqualTo("Denied");
        assertThat(jdbc.queryForObject("SELECT payload->>'reason' FROM public.audit_outbox", String.class))
                .isEqualTo("InvalidAttestation");
    }

    @Test
    void refusedMachineNamingALegitimateOne_isNotRecordedAsThatActor() throws Exception {
        // When: the caller writes the client_id of another machine, but its attestation is not valid
        tokenRequestOf("did:key:z6MkMachineOfSomeoneElse").andExpect(status().isBadRequest());

        // Then: the actor is the Verifier; the name the caller wrote is only a detail of the refusal
        assertThat(jdbc.queryForObject("SELECT payload->'actor'->>'id' FROM public.audit_outbox", String.class))
                .isEqualTo("verifier");
    }

    @Test
    void streamOfRefusalsOfOneClient_leavesOnlyTheFewTheLimitAllows() throws Exception {
        // When
        for (int i = 0; i < 20; i++) {
            tokenRequestOf("did:key:z6MkMachineThatKeepsFailing").andExpect(status().isBadRequest());
        }

        // Then
        assertThat(rowsOf(SYSTEM_AUTHENTICATED)).isEqualTo(RejectionThrottle.MAX_PER_KEY);
        assertThat(stageSpans.eventTypes()).hasSize(RejectionThrottle.MAX_PER_KEY);
    }

    @Test
    void refusalOfAnOversizedClientId_stagesNothing() throws Exception {
        // When
        tokenRequestOf("did:key:z6Mk" + "x".repeat(400)).andExpect(status().isBadRequest());

        // Then
        assertThat(jdbc.queryForObject("SELECT count(*) FROM public.audit_outbox", Integer.class)).isZero();
    }

    private int rowsOf(String eventType) {
        return jdbc.queryForObject("SELECT count(*) FROM public.audit_outbox WHERE event_type = ?",
                Integer.class, eventType);
    }

    private ResultActions tokenRequestOf(String clientId) throws Exception {
        return mockMvc.perform(post("/oidc/token")
                .with(csrf())
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param(OAuth2ParameterNames.GRANT_TYPE, "client_credentials")
                .param(OAuth2ParameterNames.CLIENT_ID, clientId)
                .param(OAuth2ParameterNames.CLIENT_ASSERTION, ASSERTION)
                .param(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE,
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
    }
}
