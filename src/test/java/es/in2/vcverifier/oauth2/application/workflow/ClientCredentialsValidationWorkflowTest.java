package es.in2.vcverifier.oauth2.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.oauth2.domain.exception.InvalidProofOfPossessionException;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchReason;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.service.CredentialSchemaDispatcher;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import es.in2.vcverifier.oauth2.domain.service.ClientAssertionValidationService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.service.VpService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ClientCredentialsValidationWorkflowTest {

    @Mock private JWTService jwtService;
    @Mock private ClientAssertionValidationService clientAssertionValidationService;
    @Mock private VpService vpService;
    @Mock private CredentialSchemaDispatcher credentialSchemaDispatcher;
    @Mock private SchemaProfileRegistry schemaProfileRegistry;

    @InjectMocks
    private ClientCredentialsValidationWorkflow workflow;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String CLIENT_ID = "did:key:z6MkClient";
    private static final String VP_TOKEN_RAW = "eyJhbGciOiJFUzI1NiJ9.vp-payload.signature";
    private static final String VP_TOKEN_B64 = Base64.getEncoder().encodeToString(VP_TOKEN_RAW.getBytes(StandardCharsets.UTF_8));
    private static final String CLIENT_ASSERTION = "client-assertion-jwt";

    private ObjectNode buildMachineCredential() {
        ObjectNode credential = OBJECT_MAPPER.createObjectNode();
        ArrayNode typeArray = credential.putArray("type");
        typeArray.add("VerifiableCredential");
        typeArray.add("learcredential.machine.w3c.3");
        return credential;
    }

    private ObjectNode buildEmployeeCredential() {
        ObjectNode credential = OBJECT_MAPPER.createObjectNode();
        ArrayNode typeArray = credential.putArray("type");
        typeArray.add("VerifiableCredential");
        typeArray.add("learcredential.employee.w3c.4");
        return credential;
    }

    @Test
    @DisplayName("execute() validates M2M flow and returns credential")
    void execute_validatesAndReturnsCredential() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        ObjectNode credential = buildMachineCredential();

        when(jwtService.parseJWT(CLIENT_ASSERTION)).thenReturn(signedJWT);
        when(jwtService.extractPayloadFromSignedJWT(signedJWT)).thenReturn(payload);
        when(jwtService.extractClaimFromPayload(payload, "vp_token")).thenReturn(VP_TOKEN_B64);
        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(VP_TOKEN_RAW)).thenReturn(credential);
        when(credentialSchemaDispatcher.dispatch(credential)).thenReturn(
            DispatchDecision.permitted("learcredential.machine.w3c.3", CredentialFormat.BUMPED_V2_0, DispatchReason.BY_TYPE));
        when(schemaProfileRegistry.findByConfigId("learcredential.machine.w3c.3")).thenReturn(
                Optional.of(new SchemaProfile("learcredential.machine.w3c.3", null, null, null, Set.of("client_credentials", "authorization_code"), false, null, null)));
        when(clientAssertionValidationService.verifyClientAssertionJWTClaims(eq(CLIENT_ID), eq(payload))).thenReturn(true);

        JsonNode result = workflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION);

        assertThat(result).isEqualTo(credential);
        verify(vpService).verifyVerifiablePresentation(VP_TOKEN_RAW, false);
    }

    @Test
    @DisplayName("execute() throws when credential is not a machine credential")
    void execute_throwsForWrongCredentialType() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        ObjectNode credential = buildEmployeeCredential();

        when(jwtService.parseJWT(CLIENT_ASSERTION)).thenReturn(signedJWT);
        when(jwtService.extractPayloadFromSignedJWT(signedJWT)).thenReturn(payload);
        when(jwtService.extractClaimFromPayload(payload, "vp_token")).thenReturn(VP_TOKEN_B64);
        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(VP_TOKEN_RAW)).thenReturn(credential);
        when(credentialSchemaDispatcher.dispatch(credential)).thenReturn(
            DispatchDecision.permitted("learcredential.employee.w3c.4", CredentialFormat.LEGACY_V1_1, DispatchReason.BY_TYPE));
        when(schemaProfileRegistry.findByConfigId("learcredential.employee.w3c.4")).thenReturn(
                Optional.of(new SchemaProfile("learcredential.employee.w3c.4", null, null, null, Set.of("authorization_code"), false, null, null)));

        assertThatThrownBy(() -> workflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                .isInstanceOf(InvalidCredentialTypeException.class)
                .hasMessageContaining("not eligible for client_credentials");

        verify(vpService, never()).verifyVerifiablePresentation(any());
    }

    @Test
    @DisplayName("execute() throws InvalidProofOfPossessionException when client assertion claims are invalid (AC-01)")
    void execute_throwsForInvalidClaims() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        ObjectNode credential = buildMachineCredential();

        when(jwtService.parseJWT(CLIENT_ASSERTION)).thenReturn(signedJWT);
        when(jwtService.extractPayloadFromSignedJWT(signedJWT)).thenReturn(payload);
        when(jwtService.extractClaimFromPayload(payload, "vp_token")).thenReturn(VP_TOKEN_B64);
        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(VP_TOKEN_RAW)).thenReturn(credential);
        when(credentialSchemaDispatcher.dispatch(credential)).thenReturn(
            DispatchDecision.permitted("learcredential.machine.w3c.3", CredentialFormat.BUMPED_V2_0, DispatchReason.BY_TYPE));
        when(schemaProfileRegistry.findByConfigId("learcredential.machine.w3c.3")).thenReturn(
                Optional.of(new SchemaProfile("learcredential.machine.w3c.3", null, null, null, Set.of("client_credentials"), false, null, null)));
        when(clientAssertionValidationService.verifyClientAssertionJWTClaims(eq(CLIENT_ID), eq(payload))).thenReturn(false);

        assertThatThrownBy(() -> workflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                .isInstanceOf(InvalidProofOfPossessionException.class)
                .hasMessageContaining("Invalid JWT claims");

        verify(vpService, never()).verifyVerifiablePresentation(any());
    }

    @Test
    @DisplayName("execute() throws InvalidProofOfPossessionException on jti replay, indistinguishable from any other invalid claim at this layer (ES-03)")
    void execute_throwsForReplayedJti() {
        // ClientAssertionValidationService.verifyClientAssertionJWTClaims already rejects a replayed jti
        // by returning false (jti-cache lookup happens inside that service, not in this workflow).
        // From this workflow's perspective a replay is just another "false" — same reason as any other
        // invalid claim (signature, iss, sub, aud, exp), which is exactly what makes AC-01 and ES-03
        // share the same InvalidProofOfPossessionException / reason=invalid_proof_of_possession.
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        ObjectNode credential = buildMachineCredential();

        when(jwtService.parseJWT(CLIENT_ASSERTION)).thenReturn(signedJWT);
        when(jwtService.extractPayloadFromSignedJWT(signedJWT)).thenReturn(payload);
        when(jwtService.extractClaimFromPayload(payload, "vp_token")).thenReturn(VP_TOKEN_B64);
        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(VP_TOKEN_RAW)).thenReturn(credential);
        when(credentialSchemaDispatcher.dispatch(credential)).thenReturn(
            DispatchDecision.permitted("learcredential.machine.w3c.3", CredentialFormat.BUMPED_V2_0, DispatchReason.BY_TYPE));
        when(schemaProfileRegistry.findByConfigId("learcredential.machine.w3c.3")).thenReturn(
                Optional.of(new SchemaProfile("learcredential.machine.w3c.3", null, null, null, Set.of("client_credentials"), false, null, null)));
        when(clientAssertionValidationService.verifyClientAssertionJWTClaims(eq(CLIENT_ID), eq(payload))).thenReturn(false);

        assertThatThrownBy(() -> workflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                .isInstanceOf(InvalidProofOfPossessionException.class);

        verify(vpService, never()).verifyVerifiablePresentation(any());
    }

    @Test
    @DisplayName("execute() enforces deterministic precedence: type eligibility fails before proof of possession is even checked (EC-01)")
    void execute_precedenceIsDeterministic_eligibilityBeforeProofOfPossession() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        ObjectNode credential = buildEmployeeCredential();

        when(jwtService.parseJWT(CLIENT_ASSERTION)).thenReturn(signedJWT);
        when(jwtService.extractPayloadFromSignedJWT(signedJWT)).thenReturn(payload);
        when(jwtService.extractClaimFromPayload(payload, "vp_token")).thenReturn(VP_TOKEN_B64);
        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(VP_TOKEN_RAW)).thenReturn(credential);
        when(credentialSchemaDispatcher.dispatch(credential)).thenReturn(
            DispatchDecision.permitted("learcredential.employee.w3c.4", CredentialFormat.LEGACY_V1_1, DispatchReason.BY_TYPE));
        when(schemaProfileRegistry.findByConfigId("learcredential.employee.w3c.4")).thenReturn(
                Optional.of(new SchemaProfile("learcredential.employee.w3c.4", null, null, null, Set.of("authorization_code"), false, null, null)));

        // Simultaneous second defect: even if the assertion also had an invalid proof of possession,
        // eligibility is checked first and must win — the reason must be reproducible.
        assertThatThrownBy(() -> workflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                .isInstanceOf(InvalidCredentialTypeException.class);

        verify(clientAssertionValidationService, never()).verifyClientAssertionJWTClaims(any(), any());
        verify(vpService, never()).verifyVerifiablePresentation(any());
    }

    @Test
    @DisplayName("execute() fails closed when vp_token is not Base64/JWT decodable (ES-01)")
    void execute_failsClosedForNonDecodableVpToken() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(CLIENT_ASSERTION)).thenReturn(signedJWT);
        when(jwtService.extractPayloadFromSignedJWT(signedJWT)).thenReturn(payload);
        when(jwtService.extractClaimFromPayload(payload, "vp_token")).thenReturn("not-valid-base64!!!");

        assertThatThrownBy(() -> workflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                .isInstanceOf(IllegalArgumentException.class);

        verify(vpService, never()).verifyVerifiablePresentation(any());
    }

    @Test
    @DisplayName("execute() propagates VP validation exception")
    void execute_propagatesVpValidationException() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);
        ObjectNode credential = buildMachineCredential();

        when(jwtService.parseJWT(CLIENT_ASSERTION)).thenReturn(signedJWT);
        when(jwtService.extractPayloadFromSignedJWT(signedJWT)).thenReturn(payload);
        when(jwtService.extractClaimFromPayload(payload, "vp_token")).thenReturn(VP_TOKEN_B64);
        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(VP_TOKEN_RAW)).thenReturn(credential);
        when(credentialSchemaDispatcher.dispatch(credential)).thenReturn(
            DispatchDecision.permitted("learcredential.machine.w3c.3", CredentialFormat.BUMPED_V2_0, DispatchReason.BY_TYPE));
        when(schemaProfileRegistry.findByConfigId("learcredential.machine.w3c.3")).thenReturn(
                Optional.of(new SchemaProfile("learcredential.machine.w3c.3", null, null, null, Set.of("client_credentials"), false, null, null)));
        when(clientAssertionValidationService.verifyClientAssertionJWTClaims(eq(CLIENT_ID), eq(payload))).thenReturn(true);
        doThrow(new RuntimeException("VP invalid")).when(vpService).verifyVerifiablePresentation(VP_TOKEN_RAW, false);

        assertThatThrownBy(() -> workflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("VP invalid");
    }
}
