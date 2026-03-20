package es.in2.vcverifier.integration;

import es.in2.vcverifier.integration.support.TestCredentialBuilder;
import es.in2.vcverifier.integration.support.TestCredentialBuilder.TestKeyPair;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.crypto.CryptoComponent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the H2M (Human-to-Machine) OID4VP flow.
 * <p>
 * Validates the full VP verification pipeline — from receiving a VP token
 * at /oid4vp/auth-response through credential parsing, time window validation,
 * certificate verification, issuer trust validation, and cryptographic binding.
 * <p>
 * Tests use real Spring context with real services; only the SSE emitter
 * (browser-side) is absent, which is handled gracefully.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@AutoConfigureMockMvc
class H2MFlowIntegrationTest {

    private static final String ISSUER_ORG_ID = "VATES-A15456585";
    private static final String CLIENT_ID = "vc-auth-client";
    private static final String REDIRECT_URI = "http://localhost:4200";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;

    @Autowired
    private CacheStore<String> cacheForNonceByState;

    @Autowired
    private CryptoComponent cryptoComponent;

    private TestKeyPair issuerKeyPair;
    private TestKeyPair holderKeyPair;

    @BeforeEach
    void setUp() {
        issuerKeyPair = TestCredentialBuilder.generateKeyPair();
        holderKeyPair = TestCredentialBuilder.generateKeyPair();
    }

    // ── H2M: LEARCredentialEmployee W3C ─────────────────────────

    @Test
    @DisplayName("H2M — LEARCredentialEmployee W3C VCDM 2.0: full VP validation succeeds")
    void h2m_employeeW3c_shouldAcceptValidPresentation() throws Exception {
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        cacheAuthorizationRequest(state, nonce);

        String audience = cryptoComponent.getClientId();
        Map<String, Object> vcPayload = TestCredentialBuilder.employeeW3cPayload(ISSUER_ORG_ID);
        String vpTokenBase64 = TestCredentialBuilder.buildBase64VpToken(
                issuerKeyPair, holderKeyPair, ISSUER_ORG_ID, vcPayload, audience, nonce);

        mockMvc.perform(post("/oid4vp/auth-response")
                        .param("state", state)
                        .param("vp_token", vpTokenBase64))
                .andExpect(status().isOk());

        // Verify the state was consumed from the cache (flow completed successfully)
        assertThatThrownBy(() -> cacheStoreForOAuth2AuthorizationRequest.get(state))
                .isInstanceOf(java.util.NoSuchElementException.class);
    }

    // ── H2M: LEARCredentialMachine W3C (negative — should reject) ────

    @Test
    @DisplayName("H2M — LEARCredentialMachine W3C: not rejected at H2M level (type validation is per-flow)")
    void h2m_machineW3c_shouldAcceptValidPresentation() throws Exception {
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        cacheAuthorizationRequest(state, nonce);

        String audience = cryptoComponent.getClientId();
        Map<String, Object> vcPayload = TestCredentialBuilder.machineW3cPayload(ISSUER_ORG_ID);
        String vpTokenBase64 = TestCredentialBuilder.buildBase64VpToken(
                issuerKeyPair, holderKeyPair, ISSUER_ORG_ID, vcPayload, audience, nonce);

        // H2M flow does not filter by credential type — it accepts any trusted credential.
        // Type restriction is enforced by the M2M client_credentials flow.
        mockMvc.perform(post("/oid4vp/auth-response")
                        .param("state", state)
                        .param("vp_token", vpTokenBase64))
                .andExpect(status().isOk());
    }

    // ── H2M: Expired credential ─────────────────────────────────

    @Test
    @DisplayName("H2M — Expired credential should be rejected")
    void h2m_expiredCredential_shouldBeRejected() throws Exception {
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        cacheAuthorizationRequest(state, nonce);

        String audience = cryptoComponent.getClientId();
        Map<String, Object> vcPayload = new HashMap<>(TestCredentialBuilder.employeeW3cPayload(ISSUER_ORG_ID));
        vcPayload.put("validUntil", "2020-01-01T00:00:00Z");

        String vpTokenBase64 = TestCredentialBuilder.buildBase64VpToken(
                issuerKeyPair, holderKeyPair, ISSUER_ORG_ID, vcPayload, audience, nonce);

        mockMvc.perform(post("/oid4vp/auth-response")
                        .param("state", state)
                        .param("vp_token", vpTokenBase64))
                .andExpect(status().isUnauthorized());
    }

    // ── H2M: Untrusted issuer ───────────────────────────────────

    @Test
    @DisplayName("H2M — Untrusted issuer should be rejected")
    void h2m_untrustedIssuer_shouldBeRejected() throws Exception {
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        cacheAuthorizationRequest(state, nonce);

        String audience = cryptoComponent.getClientId();
        String untrustedOrgId = "VATES-UNTRUSTED";
        Map<String, Object> vcPayload = TestCredentialBuilder.employeeW3cPayload(untrustedOrgId);
        String vpTokenBase64 = TestCredentialBuilder.buildBase64VpToken(
                issuerKeyPair, holderKeyPair, untrustedOrgId, vcPayload, audience, nonce);

        mockMvc.perform(post("/oid4vp/auth-response")
                        .param("state", state)
                        .param("vp_token", vpTokenBase64))
                .andExpect(status().isUnauthorized());
    }

    // ── H2M: Invalid state (replay protection) ──────────────────

    @Test
    @DisplayName("H2M — Unknown state should be rejected")
    void h2m_unknownState_shouldBeRejected() throws Exception {
        String audience = cryptoComponent.getClientId();
        Map<String, Object> vcPayload = TestCredentialBuilder.employeeW3cPayload(ISSUER_ORG_ID);
        String vpTokenBase64 = TestCredentialBuilder.buildBase64VpToken(
                issuerKeyPair, holderKeyPair, ISSUER_ORG_ID, vcPayload, audience, "some-nonce");

        mockMvc.perform(post("/oid4vp/auth-response")
                        .param("state", "non-existent-state")
                        .param("vp_token", vpTokenBase64))
                .andExpect(status().isNotFound());
    }

    // ── H2M: LEARCredentialEmployee SD-JWT ─────────────────────────

    @Test
    @DisplayName("H2M — LEARCredentialEmployee SD-JWT: full SD-JWT verification succeeds")
    void h2m_employeeSdJwt_shouldAcceptValidPresentation() throws Exception {
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        cacheAuthorizationRequest(state, nonce);

        String audience = cryptoComponent.getClientId();
        String vpTokenBase64 = TestCredentialBuilder.buildBase64SdJwtVpToken(
                issuerKeyPair, holderKeyPair, ISSUER_ORG_ID,
                "learcredential.employee.sd.1",
                TestCredentialBuilder.employeeSdJwtDisclosedClaims(ISSUER_ORG_ID),
                Map.of(),
                audience, nonce);

        mockMvc.perform(post("/oid4vp/auth-response")
                        .param("state", state)
                        .param("vp_token", vpTokenBase64))
                .andExpect(status().isOk());

        assertThatThrownBy(() -> cacheStoreForOAuth2AuthorizationRequest.get(state))
                .isInstanceOf(java.util.NoSuchElementException.class);
    }

    // ── H2M: LEARCredentialMachine SD-JWT ────────────────────────

    @Test
    @DisplayName("H2M — LEARCredentialMachine SD-JWT: full SD-JWT verification succeeds")
    void h2m_machineSdJwt_shouldAcceptValidPresentation() throws Exception {
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        cacheAuthorizationRequest(state, nonce);

        String audience = cryptoComponent.getClientId();
        String vpTokenBase64 = TestCredentialBuilder.buildBase64SdJwtVpToken(
                issuerKeyPair, holderKeyPair, ISSUER_ORG_ID,
                "learcredential.machine.sd.1",
                TestCredentialBuilder.machineSdJwtDisclosedClaims(ISSUER_ORG_ID),
                Map.of(),
                audience, nonce);

        mockMvc.perform(post("/oid4vp/auth-response")
                        .param("state", state)
                        .param("vp_token", vpTokenBase64))
                .andExpect(status().isOk());
    }

    // ── Cache helper ─────────────────────────────────────────────

    private void cacheAuthorizationRequest(String state, String nonce) {
        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(EXPIRATION, Instant.now().plusSeconds(120).getEpochSecond());
        additionalParams.put("nonce", nonce);

        OAuth2AuthorizationRequest authRequest = OAuth2AuthorizationRequest.authorizationCode()
                .state(state)
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .scope("openid", "learcredential")
                .authorizationUri("http://localhost:8080")
                .additionalParameters(additionalParams)
                .build();

        cacheStoreForOAuth2AuthorizationRequest.add(state, authRequest);
        cacheForNonceByState.add(state, nonce);
    }
}
