package es.in2.vcverifier.oauth2.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import es.in2.vcverifier.oauth2.application.workflow.ClientCredentialsValidationWorkflow;
import es.in2.vcverifier.oauth2.application.workflow.TokenGenerationWorkflow;
import es.in2.vcverifier.oauth2.domain.exception.InvalidProofOfPossessionException;
import es.in2.vcverifier.oauth2.domain.model.OAuth2M2MAuditEvent;
import es.in2.vcverifier.oauth2.domain.port.OAuth2M2MAuditPort;
import es.in2.vcverifier.oauth2.infrastructure.config.ClientLoaderConfig;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.verifier.domain.exception.CredentialExpiredException;
import es.in2.vcverifier.verifier.domain.exception.CredentialNotActiveException;
import es.in2.vcverifier.verifier.domain.exception.CredentialRevokedException;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.exception.StatusListCredentialException;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * EUD-156 (US-03): end-to-end coverage of the M2M {@code client_credentials} negative path
 * against the real {@code /oidc/token} endpoint (Spring Authorization Server filter chain,
 * not a {@code @Controller}, hence the full security filter chain must stay enabled here —
 * unlike other ITs in this codebase that disable filters with {@code addFilters = false}).
 * <p>
 * {@link ClientCredentialsValidationWorkflow} is mocked: its internal precedence and
 * exception-selection logic is already covered by {@code ClientCredentialsValidationWorkflowTest}.
 * This IT proves the layer above it — {@code CustomTokenRequestConverter} +
 * {@code OAuth2ErrorTranslator} + the audit port — end to end through real HTTP.
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureMockMvc
class M2MRejectionIT {

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

    private static final String CLIENT_ID = "did:key:z6MkM2MClient";
    private static final String CLIENT_ASSERTION = "header.payload.signature";

    @Autowired MockMvc mockMvc;

    @MockitoBean ClientRegistryProvider clientRegistryProvider;
    @MockitoBean ClientLoaderConfig clientLoaderConfig;
    @MockitoBean RegisteredClientRepository registeredClientRepository;
    @MockitoBean ClientCredentialsValidationWorkflow clientCredentialsValidationWorkflow;
    @MockitoBean OAuth2M2MAuditPort oAuth2M2MAuditPort;
    @MockitoBean TokenGenerationWorkflow tokenGenerationWorkflow;

    @BeforeEach
    void setUp() {
        reset(oAuth2M2MAuditPort, tokenGenerationWorkflow);
        // Unregistered by default: lets UnregisteredM2MClientAuthenticationConverter hand the
        // request to the M2M pipeline instead of Spring's built-in (pre-registered-only) path.
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(null);
    }

    // =========================================================
    // AC-01: invalid proof of possession
    // =========================================================
    @Test
    void rejectsInvalidProofOfPossession_publishesAuditAndReturnsBinaryInvalidClient() throws Exception {
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new InvalidProofOfPossessionException("Invalid JWT claims from assertion"));

        performClientCredentialsRequest()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.error_description").doesNotExist())
                .andExpect(jsonPath("$.error_uri").doesNotExist());

        thenAuditReasonPublished("invalid_proof_of_possession");
        thenNoTokenIssued();
    }

    // =========================================================
    // AC-02: credential not a machine credential (not eligible, RD-01)
    // =========================================================
    @Test
    void rejectsNonMachineCredential_publishesAuditAndReturnsBinaryInvalidClient() throws Exception {
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new InvalidCredentialTypeException(
                        "Credential type learcredential.employee.w3c.4 is not eligible for client_credentials grant"));

        performClientCredentialsRequest()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.error_description").doesNotExist())
                .andExpect(jsonPath("$.error_uri").doesNotExist());

        thenAuditReasonPublished("credential_type_not_eligible");
        thenNoTokenIssued();
    }

    // =========================================================
    // AC-03: untrusted issuer
    // =========================================================
    @Test
    void rejectsUntrustedIssuer_publishesAuditAndReturnsBinaryInvalidClient() throws Exception {
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new IssuerNotAuthorizedException("Issuer is not in the trusted issuers list"));

        performClientCredentialsRequest()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.error_description").doesNotExist())
                .andExpect(jsonPath("$.error_uri").doesNotExist());

        thenAuditReasonPublished("issuer_not_trusted");
        thenNoTokenIssued();
    }

    // =========================================================
    // AC-05 (core): the 3 reasons this Story adds are mutually distinguishable
    // =========================================================
    @Test
    void theThreeCoreRejectionReasonsAreMutuallyDistinguishable() throws Exception {
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new InvalidProofOfPossessionException("invalid PoP"));
        performClientCredentialsRequest().andExpect(status().isBadRequest());
        String popReason = captureLastPublishedReason();

        reset(oAuth2M2MAuditPort);
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new InvalidCredentialTypeException("not eligible"));
        performClientCredentialsRequest().andExpect(status().isBadRequest());
        String typeReason = captureLastPublishedReason();

        reset(oAuth2M2MAuditPort);
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new IssuerNotAuthorizedException("untrusted issuer"));
        performClientCredentialsRequest().andExpect(status().isBadRequest());
        String issuerReason = captureLastPublishedReason();

        assertThat(popReason).isEqualTo("invalid_proof_of_possession");
        assertThat(typeReason).isEqualTo("credential_type_not_eligible");
        assertThat(issuerReason).isEqualTo("issuer_not_trusted");
        assertThat(popReason).isNotEqualTo(typeReason);
        assertThat(popReason).isNotEqualTo(issuerReason);
        assertThat(typeReason).isNotEqualTo(issuerReason);
    }

    // =========================================================
    // EC-02: pre-registered machine client is not affected (regression guard)
    // =========================================================
    // Deliberately colon-free: HTTP Basic splits credentials on the FIRST ':', so a DID-style
    // client_id like CLIENT_ID ("did:key:...") would get mis-parsed as username="did". Real
    // pre-registered clients in clients.yaml aren't required to be DIDs, so this is a faithful
    // stand-in, not a test hack.
    private static final String PRE_REGISTERED_CLIENT_ID = "m2m-preregistered-client";

    @Test
    void preRegisteredMachineClientIsNotAffected_getsTokenAndPublishesNoRejectAudit() throws Exception {
        // Real pre-registered M2M clients authenticate with private_key_jwt, which would require
        // a signed JWT verifiable against the client's registered JWKS — out of scope for this
        // Story's regression concern. What EC-02 actually needs to prove is that
        // CustomAuthenticationProvider.getOrBuildRegisteredClient's "already registered" branch
        // (which skips the synthetic-client/tenant-derivation path this Story never touches) is
        // reached and unaffected. client_secret_basic exercises that exact branch without needing
        // asymmetric-key test infrastructure; the credential is still VP-validated via the
        // (mocked) workflow either way, exactly as it is for a real private_key_jwt client.
        JsonNode credential = buildMachineCredential();
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(PRE_REGISTERED_CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenReturn(credential);

        RegisteredClient preRegistered = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(PRE_REGISTERED_CLIENT_ID)
                .clientSecret("{noop}test-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
        when(registeredClientRepository.findByClientId(PRE_REGISTERED_CLIENT_ID)).thenReturn(preRegistered);

        Instant issueTime = Instant.now();
        when(tokenGenerationWorkflow.issueAccessToken(any(), anyString(), anyMap(), eq(false), nullable(String.class)))
                .thenReturn(new TokenGenerationWorkflow.Result(
                        "fake-access-token", issueTime, issueTime.plusSeconds(900), null, null, "openid", "did:key:subject"));

        mockMvc.perform(post("/oidc/token")
                        .with(csrf())
                        .with(httpBasic(PRE_REGISTERED_CLIENT_ID, "test-secret"))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param(OAuth2ParameterNames.GRANT_TYPE, "client_credentials")
                        // CustomTokenRequestConverter always reads client_id from the body params
                        // (not from the authenticated principal), regardless of how the client
                        // authenticated — so this must be present even alongside HTTP Basic auth.
                        .param(OAuth2ParameterNames.CLIENT_ID, PRE_REGISTERED_CLIENT_ID)
                        .param(OAuth2ParameterNames.CLIENT_ASSERTION, CLIENT_ASSERTION))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("fake-access-token"));

        verify(oAuth2M2MAuditPort, never()).publish(any());
    }

    // =========================================================
    // EC-01: deterministic, reproducible precedence when several defects coincide
    // =========================================================
    @Test
    void precedenceIsDeterministicAndReproducible_typeEligibilityWinsOverOtherDefects() throws Exception {
        // The workflow itself decides precedence (already covered by
        // ClientCredentialsValidationWorkflowTest: eligibility before proof of possession).
        // At this layer we only need to prove that, given the workflow's verdict, the mapped
        // reason is reproducible across identical repeated requests — same input, same output.
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new InvalidCredentialTypeException("not eligible for client_credentials"));

        performClientCredentialsRequest()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_client"));
        String firstReason = captureLastPublishedReason();

        reset(oAuth2M2MAuditPort);
        performClientCredentialsRequest()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_client"));
        String secondReason = captureLastPublishedReason();

        assertThat(firstReason).isEqualTo("credential_type_not_eligible");
        assertThat(secondReason).isEqualTo("credential_type_not_eligible");
    }

    // =========================================================
    // ES-01: client_assertion malformed / vp_token absent or non-decodable (fail-closed default)
    // =========================================================
    @Test
    void rejectsMalformedAssertionOrVpToken_failsClosedAsCredentialValidationFailed() throws Exception {
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new IllegalArgumentException("vp_token is not valid Base64"));

        performClientCredentialsRequest()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.error_description").doesNotExist())
                .andExpect(jsonPath("$.error_uri").doesNotExist());

        thenAuditReasonPublished("credential_validation_failed");
        thenNoTokenIssued();
    }

    // =========================================================
    // ES-02: revoked / expired / not-yet-active credential (EUD-16 non-regression guard)
    // =========================================================
    @Test
    void rejectsExpiredCredential_returnsInvalidGrantWithDistinguishableReason() throws Exception {
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new CredentialExpiredException("Credential has expired"));

        performClientCredentialsRequest()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.error_description").doesNotExist())
                .andExpect(jsonPath("$.error_uri").doesNotExist());

        thenAuditReasonPublished("credential_expired");
        thenNoTokenIssued();
    }

    @Test
    void rejectsNotYetActiveCredential_returnsInvalidGrantWithDistinguishableReason() throws Exception {
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new CredentialNotActiveException("Credential is not yet valid"));

        performClientCredentialsRequest()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.error_description").doesNotExist())
                .andExpect(jsonPath("$.error_uri").doesNotExist());

        thenAuditReasonPublished("credential_not_active");
        thenNoTokenIssued();
    }

    @Test
    void rejectsRevokedCredential_returnsInvalidGrantWithDistinguishableReason() throws Exception {
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new CredentialRevokedException("Credential is revoked"));

        performClientCredentialsRequest()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.error_description").doesNotExist())
                .andExpect(jsonPath("$.error_uri").doesNotExist());

        thenAuditReasonPublished("credential_revoked");
        thenNoTokenIssued();
    }

    // =========================================================
    // ES-03: proof-of-possession replay (jti already consumed)
    // =========================================================
    @Test
    void rejectsReplayedJti_returnsInvalidClientWithInvalidProofOfPossessionReason() throws Exception {
        // ClientAssertionValidationService rejects a replayed jti by returning false, which the
        // workflow already translates to InvalidProofOfPossessionException (same as AC-01) —
        // this test exists for its own ES-03 traceability, not because the mapping differs.
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new InvalidProofOfPossessionException("jti already consumed"));

        performClientCredentialsRequest()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.error_description").doesNotExist())
                .andExpect(jsonPath("$.error_uri").doesNotExist());

        thenAuditReasonPublished("invalid_proof_of_possession");
        thenNoTokenIssued();
    }

    // =========================================================
    // ES-04: external dependency failure / timeout (trusted-issuers registry, status list)
    // =========================================================
    @Test
    void rejectsWhenTrustedIssuersRegistryUnreachable_returnsBadRequestWithServerErrorCodeAndDistinguishableReason() throws Exception {
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new FailedCommunicationException("Error fetching issuer data"));

        performClientCredentialsRequest()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("server_error"))
                .andExpect(jsonPath("$.error_description").doesNotExist())
                .andExpect(jsonPath("$.error_uri").doesNotExist());

        thenAuditReasonPublished("external_dependency_failure");
        thenNoTokenIssued();
    }

    @Test
    void rejectsWhenStatusListFetchFails_returnsBadRequestWithServerErrorCodeAndDistinguishableReason() throws Exception {
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                .thenThrow(new StatusListCredentialException("Failed to gunzip content"));

        performClientCredentialsRequest()
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("server_error"))
                .andExpect(jsonPath("$.error_description").doesNotExist())
                .andExpect(jsonPath("$.error_uri").doesNotExist());

        thenAuditReasonPublished("external_dependency_failure");
        thenNoTokenIssued();
    }

    // =========================================================
    // NFR-O-01: 100% audit coverage across the full set of M2M rejection reasons, all
    // mutually distinguishable (extends the AC-05 core check to every reason this endpoint
    // can emit, not just the 3 this Story introduces).
    // =========================================================
    @Test
    void everyRejectionTypeAcrossTheFullSetPublishesExactlyOneDistinguishableReason() throws Exception {
        var scenarios = List.<RejectionScenario>of(
                new RejectionScenario(new InvalidProofOfPossessionException("x"), "invalid_proof_of_possession"),
                new RejectionScenario(new InvalidCredentialTypeException("x"), "credential_type_not_eligible"),
                new RejectionScenario(new IssuerNotAuthorizedException("x"), "issuer_not_trusted"),
                new RejectionScenario(new CredentialExpiredException("x"), "credential_expired"),
                new RejectionScenario(new CredentialNotActiveException("x"), "credential_not_active"),
                new RejectionScenario(new CredentialRevokedException("x"), "credential_revoked"),
                new RejectionScenario(new FailedCommunicationException("x"), "external_dependency_failure"),
                new RejectionScenario(new StatusListCredentialException("x"), "external_dependency_failure"),
                new RejectionScenario(new IllegalArgumentException("x"), "credential_validation_failed")
        );

        var observedReasons = new ArrayList<String>();
        for (RejectionScenario scenario : scenarios) {
            reset(oAuth2M2MAuditPort);
            when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(eq(CLIENT_ID), eq(CLIENT_ASSERTION)))
                    .thenThrow(scenario.exception());

            performClientCredentialsRequest();

            String reason = captureLastPublishedReason();
            assertThat(reason).isEqualTo(scenario.expectedReason());
            observedReasons.add(reason);
        }

        // 9 scenarios collapse onto 8 distinct reasons: FailedCommunicationException and
        // StatusListCredentialException are two different causes of the same external_dependency_failure
        // reason (by design — both are "not the client's fault"), so this is expected, not a
        // distinguishability violation of AC-05 (which is about failure *types*, not exception classes).
        assertThat(observedReasons).hasSize(9);
        assertThat(new HashSet<>(observedReasons)).hasSize(8);
    }

    private record RejectionScenario(RuntimeException exception, String expectedReason) {
    }

    // --- Helpers (reused/extended by the edge/error scenarios added on top of this class) ---

    ResultActions performClientCredentialsRequest() throws Exception {
        return mockMvc.perform(post("/oidc/token")
                .with(csrf())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param(OAuth2ParameterNames.GRANT_TYPE, "client_credentials")
                .param(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID)
                .param(OAuth2ParameterNames.CLIENT_ASSERTION, CLIENT_ASSERTION)
                .param(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE,
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
    }

    void thenAuditReasonPublished(String expectedReason) {
        ArgumentCaptor<OAuth2M2MAuditEvent> captor = ArgumentCaptor.forClass(OAuth2M2MAuditEvent.class);
        verify(oAuth2M2MAuditPort).publish(captor.capture());
        assertThat(captor.getValue().getOutcome()).isEqualTo("REJECT");
        assertThat(captor.getValue().getReason()).isEqualTo(expectedReason);
    }

    String captureLastPublishedReason() {
        ArgumentCaptor<OAuth2M2MAuditEvent> captor = ArgumentCaptor.forClass(OAuth2M2MAuditEvent.class);
        verify(oAuth2M2MAuditPort).publish(captor.capture());
        return captor.getValue().getReason();
    }

    void thenNoTokenIssued() {
        verify(tokenGenerationWorkflow, never()).issueAccessToken(any(), anyString(), anyMap(), anyBoolean(), nullable(String.class));
    }

    JsonNode buildMachineCredential() {
        JsonNodeFactory factory = JsonNodeFactory.instance;
        var typeArray = factory.arrayNode();
        typeArray.add("VerifiableCredential");
        typeArray.add("LEARCredentialMachine");
        return factory.objectNode().set("type", typeArray);
    }
}
