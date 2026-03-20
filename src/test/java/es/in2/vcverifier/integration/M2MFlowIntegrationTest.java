package es.in2.vcverifier.integration;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.integration.support.TestCredentialBuilder;
import es.in2.vcverifier.integration.support.TestCredentialBuilder.TestKeyPair;
import es.in2.vcverifier.oauth2.application.workflow.ClientCredentialsValidationWorkflow;
import es.in2.vcverifier.shared.config.VerifierConfig;
import es.in2.vcverifier.shared.crypto.CryptoComponent;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration tests for the M2M (Machine-to-Machine) client_credentials flow.
 * <p>
 * Validates the full pipeline: client_assertion JWT parsing, VP extraction,
 * credential type enforcement (only machine credentials allowed), VP validation
 * (certificate, time window, issuer trust, cryptographic binding).
 * <p>
 * Uses the real Spring context — all services wired as in production.
 * The workflow is called directly (not via HTTP) because the /oidc/token endpoint
 * requires Spring Authorization Server client authentication, which is orthogonal
 * to the VP validation logic being tested here.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class M2MFlowIntegrationTest {

    private static final String ISSUER_ORG_ID = "VATES-A15456585";
    private static final String M2M_CLIENT_ID = "m2m-test-client";

    @Autowired
    private ClientCredentialsValidationWorkflow clientCredentialsValidationWorkflow;

    @Autowired
    private CryptoComponent cryptoComponent;

    @Autowired
    private VerifierConfig verifierConfig;

    private TestKeyPair issuerKeyPair;
    private TestKeyPair holderKeyPair;

    @BeforeEach
    void setUp() {
        issuerKeyPair = TestCredentialBuilder.generateKeyPair();
        holderKeyPair = TestCredentialBuilder.generateKeyPair();
    }

    // ── M2M: LEARCredentialMachine W3C ──────────────────────────

    @Test
    @DisplayName("M2M — LEARCredentialMachine W3C: full validation succeeds")
    void m2m_machineW3c_shouldAcceptValidCredential() {
        Map<String, Object> vcPayload = TestCredentialBuilder.machineW3cPayload(ISSUER_ORG_ID);
        String vpAudience = cryptoComponent.getClientId();
        String assertionAudience = verifierConfig.getStaticUrl();

        String vcJwt = TestCredentialBuilder.buildVcJwt(
                issuerKeyPair, holderKeyPair, ISSUER_ORG_ID, vcPayload);
        String vpJwt = TestCredentialBuilder.buildVpJwt(
                holderKeyPair, List.of(vcJwt), vpAudience, null);
        String clientAssertion = TestCredentialBuilder.buildClientAssertionJwt(
                holderKeyPair, vpJwt, assertionAudience, M2M_CLIENT_ID);

        JsonNode result = clientCredentialsValidationWorkflow
                .validateClientCredentialsGrant(M2M_CLIENT_ID, clientAssertion);

        assertThat(result).isNotNull();
        assertThat(result.get("type").toString()).contains("learcredential.machine.w3c.3");
    }

    // ── M2M: LEARCredentialEmployee W3C (rejected — not a machine credential) ──

    @Test
    @DisplayName("M2M — LEARCredentialEmployee W3C: rejected (not a machine credential)")
    void m2m_employeeW3c_shouldBeRejected() {
        Map<String, Object> vcPayload = TestCredentialBuilder.employeeW3cPayload(ISSUER_ORG_ID);
        String vpAudience = cryptoComponent.getClientId();
        String assertionAudience = verifierConfig.getStaticUrl();

        String vcJwt = TestCredentialBuilder.buildVcJwt(
                issuerKeyPair, holderKeyPair, ISSUER_ORG_ID, vcPayload);
        String vpJwt = TestCredentialBuilder.buildVpJwt(
                holderKeyPair, List.of(vcJwt), vpAudience, null);
        String clientAssertion = TestCredentialBuilder.buildClientAssertionJwt(
                holderKeyPair, vpJwt, assertionAudience, M2M_CLIENT_ID);

        assertThatThrownBy(() ->
                clientCredentialsValidationWorkflow
                        .validateClientCredentialsGrant(M2M_CLIENT_ID, clientAssertion))
                .isInstanceOf(InvalidCredentialTypeException.class);
    }

    // ── M2M: Expired credential ─────────────────────────────────

    @Test
    @DisplayName("M2M — Expired machine credential should be rejected")
    void m2m_expiredCredential_shouldBeRejected() {
        Map<String, Object> vcPayload = new java.util.HashMap<>(
                TestCredentialBuilder.machineW3cPayload(ISSUER_ORG_ID));
        vcPayload.put("validUntil", "2020-01-01T00:00:00Z");

        String vpAudience = cryptoComponent.getClientId();
        String assertionAudience = verifierConfig.getStaticUrl();
        String vcJwt = TestCredentialBuilder.buildVcJwt(
                issuerKeyPair, holderKeyPair, ISSUER_ORG_ID, vcPayload);
        String vpJwt = TestCredentialBuilder.buildVpJwt(
                holderKeyPair, List.of(vcJwt), vpAudience, null);
        String clientAssertion = TestCredentialBuilder.buildClientAssertionJwt(
                holderKeyPair, vpJwt, assertionAudience, M2M_CLIENT_ID);

        assertThatThrownBy(() ->
                clientCredentialsValidationWorkflow
                        .validateClientCredentialsGrant(M2M_CLIENT_ID, clientAssertion))
                .hasMessageContaining("expired");
    }

    // ── M2M: Untrusted issuer ───────────────────────────────────

    @Test
    @DisplayName("M2M — Untrusted issuer should be rejected")
    void m2m_untrustedIssuer_shouldBeRejected() {
        String untrustedOrgId = "VATES-UNTRUSTED";
        Map<String, Object> vcPayload = TestCredentialBuilder.machineW3cPayload(untrustedOrgId);
        String vpAudience = cryptoComponent.getClientId();
        String assertionAudience = verifierConfig.getStaticUrl();

        String vcJwt = TestCredentialBuilder.buildVcJwt(
                issuerKeyPair, holderKeyPair, untrustedOrgId, vcPayload);
        String vpJwt = TestCredentialBuilder.buildVpJwt(
                holderKeyPair, List.of(vcJwt), vpAudience, null);
        String clientAssertion = TestCredentialBuilder.buildClientAssertionJwt(
                holderKeyPair, vpJwt, assertionAudience, M2M_CLIENT_ID);

        assertThatThrownBy(() ->
                clientCredentialsValidationWorkflow
                        .validateClientCredentialsGrant(M2M_CLIENT_ID, clientAssertion))
                .hasMessageContaining("not found");
    }

    // ── M2M: Cryptographic binding mismatch ─────────────────────

    @Test
    @DisplayName("M2M — VP signed with different key than VC cnf.jwk should be rejected")
    void m2m_bindingMismatch_shouldBeRejected() {
        TestKeyPair attackerKeyPair = TestCredentialBuilder.generateKeyPair();
        Map<String, Object> vcPayload = TestCredentialBuilder.machineW3cPayload(ISSUER_ORG_ID);
        String vpAudience = cryptoComponent.getClientId();
        String assertionAudience = verifierConfig.getStaticUrl();

        // VC is bound to holderKeyPair, but VP is signed with attackerKeyPair
        String vcJwt = TestCredentialBuilder.buildVcJwt(
                issuerKeyPair, holderKeyPair, ISSUER_ORG_ID, vcPayload);
        String vpJwt = TestCredentialBuilder.buildVpJwt(
                attackerKeyPair, List.of(vcJwt), vpAudience, null);
        String clientAssertion = TestCredentialBuilder.buildClientAssertionJwt(
                attackerKeyPair, vpJwt, assertionAudience, M2M_CLIENT_ID);

        assertThatThrownBy(() ->
                clientCredentialsValidationWorkflow
                        .validateClientCredentialsGrant(M2M_CLIENT_ID, clientAssertion))
                .hasMessageContaining("mismatch");
    }
}
