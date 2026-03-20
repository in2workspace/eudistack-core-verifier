package es.in2.vcverifier.verifier.infrastructure.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.crypto.CertificateValidationService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.shared.domain.exception.JWTClaimMissingException;
import es.in2.vcverifier.shared.domain.exception.JWTParsingException;
import es.in2.vcverifier.verifier.domain.exception.*;
import es.in2.vcverifier.verifier.domain.model.GenericCredential;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.verifier.domain.model.validation.RevocationPaths;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.model.validation.ValidationPaths;
import es.in2.vcverifier.verifier.domain.model.validation.ValidationResult;
import es.in2.vcverifier.verifier.domain.service.CredentialStatusVerifier;
import es.in2.vcverifier.verifier.domain.service.CredentialValidator;
import es.in2.vcverifier.verifier.domain.service.TrustFrameworkService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Method;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VpServiceImplTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Mock
    private JWTService jwtService;
    @Mock
    private TrustFrameworkService trustFrameworkService;
    @Mock
    private CertificateValidationService certificateValidationService;
    @Mock
    private GenericCredentialFactory genericCredentialFactory;
    @Mock
    private CredentialValidator credentialValidator;
    @Mock
    private CryptographicBindingValidator cryptographicBindingValidator;
    @Mock
    private ObjectMapper objectMapper;
    @Mock
    private CredentialStatusVerifier bitstringStatusListVerifier;

    private VpServiceImpl vpServiceImpl;

    @BeforeEach
    void setUp() {
        vpServiceImpl = new VpServiceImpl(
                jwtService, objectMapper, trustFrameworkService,
                certificateValidationService, genericCredentialFactory,
                credentialValidator, cryptographicBindingValidator,
                List.of(bitstringStatusListVerifier)
        );
        lenient().when(credentialValidator.validate(any()))
                .thenReturn(ValidationResult.builder().valid(true).errors(List.of()).build());
    }

    // --- VP structure tests (before credential mapping) ---

    @Test
    void verifyVerifiablePresentation_vp_claim_with_verifiableCredential_claim_is_not_found_throws_CredentialException() {
        String vpClaimWithVcArrayEmpty = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbXX0sImV4cCI6MTcyMDAzMDAwMywiaWF0IjoxNzE3NDM4MDAzLCJqdGkiOiI0MWFjYWRhMy02N2I0LTQ5NGUtYTZlMy1lMDk2NjQ0OWYyNWQifQ.kR4ob7mBGb246EpUYpMRKaESEqGc7yZaNnyoZpkxbMrF_bgC9VLRmMagsHP4DXfl7f8XyBUKFyUcda2PUPs-bA";

        assertThrows(CredentialException.class, () ->
                vpServiceImpl.verifyVerifiablePresentation(vpClaimWithVcArrayEmpty)
        );
    }

    @Test
    void verifyVerifiablePresentation_vp_claim_with_verifiableCredential_claim_is_not_an_array_throws_CredentialException() {
        String vpClaimWithVcNotArrayFormat = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjoibm90LWFycmF5LWZvcm1hdCJ9LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0.0Jpm4g5IUBnZRH5Zf1FSs0nSJmdD9dQncchlFJoqT_tDU733rXLT7UbD0f4KIfwPPZn_APKNt-h5ziTQjgXJiw";

        assertThrows(CredentialException.class, () ->
                vpServiceImpl.verifyVerifiablePresentation(vpClaimWithVcNotArrayFormat)
        );
    }

    @Test
    void verifyVerifiablePresentation_vp_claim_without_verifiableCredential_claim_inside_throws_JWTClaimMissingException() {
        String vpClaimNotValidObject = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ2cCI6e319.hLaehswoW9QiU_FmLGCDZIPOvnNOvn2HsOCs9lKhHUE";

        assertThrows(JWTClaimMissingException.class, () ->
                vpServiceImpl.verifyVerifiablePresentation(vpClaimNotValidObject)
        );
    }

    @Test
    void verifyVerifiablePresentation_vp_claim_not_valid_object_throws_JWTClaimMissingException() {
        String vpClaimNotValidObject = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ2cCI6ImludmFsaWRWcEZvcm1hdCJ9.5-6R9OxqX7lXEEqVL_12Bf0UODXnkPtrt_ntoD2IrPQ";

        assertThrows(JWTClaimMissingException.class, () ->
                vpServiceImpl.verifyVerifiablePresentation(vpClaimNotValidObject)
        );
    }

    @Test
    void verifyVerifiablePresentation_invalidVP_throws_JWTClaimMissingException() {
        String jwtWithoutVpClaim = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        assertThrows(JWTClaimMissingException.class, () ->
                vpServiceImpl.verifyVerifiablePresentation(jwtWithoutVpClaim)
        );
    }

    @Test
    void verifyVerifiablePresentation_invalidVP_throws_JWTParsingException() {
        String invalidVP = "invalidVPJWT";

        assertThrows(JWTParsingException.class, () ->
                vpServiceImpl.verifyVerifiablePresentation(invalidVP)
        );
    }

    // --- Credential mapping failure tests ---

    @Test
    void verifyVerifiablePresentation_factoryThrowsCredentialMappingException() {
        String verifiablePresentation = buildVpWithInnerVc();

        Payload payload = mock(Payload.class);
        when(jwtService.extractPayloadFromSignedJWT(any(SignedJWT.class))).thenReturn(payload);
        when(genericCredentialFactory.create(payload))
                .thenThrow(new CredentialMappingException("Invalid payload format for Verifiable Credential."));

        assertThrows(CredentialMappingException.class,
                () -> vpServiceImpl.verifyVerifiablePresentation(verifiablePresentation));
    }

    @Test
    void verifyVerifiablePresentation_factoryThrowsInvalidCredentialTypeException() throws Exception {
        String vpToken = "vp.jwt";
        String vcJwt = "vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mocked = mockStatic(SignedJWT.class)) {
            mocked.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mocked.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            JWTClaimsSet vpClaims = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaims);
            when(vpClaims.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            Payload payload = mock(Payload.class);
            when(jwtService.extractPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);
            when(genericCredentialFactory.create(payload))
                    .thenThrow(new InvalidCredentialTypeException("Unsupported credential type: [invalid]"));

            assertThrows(InvalidCredentialTypeException.class,
                    () -> vpServiceImpl.verifyVerifiablePresentation(vpToken));
        }
    }

    // --- Full pipeline success tests ---

    @Test
    void validateVerifiablePresentation_success_noRevocation_noMandator() throws Exception {
        String vpToken = "valid.vp.jwt";
        String vcJwt = "valid.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mockedSignedJWT = mockStatic(SignedJWT.class)) {
            mockedSignedJWT.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mockedSignedJWT.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            JWTClaimsSet vpClaimsSet = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaimsSet);
            when(vpClaimsSet.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            JWTClaimsSet vcClaimsSet = mock(JWTClaimsSet.class);
            when(vcSignedJWT.getJWTClaimsSet()).thenReturn(vcClaimsSet);
            when(vcClaimsSet.getIssuer()).thenReturn("did:elsi:VATES-FOO");

            Payload payload = mock(Payload.class);
            when(jwtService.extractPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            GenericCredential credential = buildGenericCredential(
                    Instant.now().minus(1, ChronoUnit.MINUTES),
                    Instant.now().plus(5, ChronoUnit.MINUTES),
                    "VATES-FOO", null, null);
            when(genericCredentialFactory.create(payload)).thenReturn(credential);

            List<IssuerCredentialsCapabilities> caps = List.of(
                    IssuerCredentialsCapabilities.builder()
                            .credentialsType("LEARCredentialEmployee")
                            .validFor(null).claims(null).build()
            );
            when(trustFrameworkService.getTrustedIssuerListData("did:elsi:VATES-FOO")).thenReturn(caps);

            Map<String, Object> vcHeaderMap = new HashMap<>();
            vcHeaderMap.put("x5c", List.of("base64Cert"));
            JWSHeader vcHeader = mock(JWSHeader.class);
            when(vcSignedJWT.getHeader()).thenReturn(vcHeader);
            when(vcHeader.toJSONObject()).thenReturn(vcHeaderMap);
            when(vcSignedJWT.serialize()).thenReturn(vcJwt);

            doNothing().when(certificateValidationService)
                    .extractAndVerifyCertificate(vcJwt, vcHeaderMap, "VATES-FOO");
            doNothing().when(cryptographicBindingValidator).validateVpSignatureAndBinding(any(), any(), any());

            assertDoesNotThrow(() -> vpServiceImpl.verifyVerifiablePresentation(vpToken));
            verify(cryptographicBindingValidator).validateVpSignatureAndBinding(any(), any(), any());
        }
    }

    @Test
    void validateVerifiablePresentation_success_withMandator() throws Exception {
        String vpToken = "valid.vp.jwt";
        String vcJwt = "valid.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mockedSignedJWT = mockStatic(SignedJWT.class)) {
            mockedSignedJWT.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mockedSignedJWT.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            JWTClaimsSet vpClaimsSet = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaimsSet);
            when(vpClaimsSet.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            JWTClaimsSet vcClaimsSet = mock(JWTClaimsSet.class);
            when(vcSignedJWT.getJWTClaimsSet()).thenReturn(vcClaimsSet);
            when(vcClaimsSet.getIssuer()).thenReturn("did:elsi:issuer");

            Payload payload = mock(Payload.class);
            when(jwtService.extractPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            GenericCredential credential = buildGenericCredential(
                    Instant.now().minus(1, ChronoUnit.MINUTES),
                    Instant.now().plus(1, ChronoUnit.DAYS),
                    "issuer",
                    "credentialSubject.mandate.mandator.organizationIdentifier",
                    null);
            when(genericCredentialFactory.create(payload)).thenReturn(credential);

            List<IssuerCredentialsCapabilities> caps = List.of(
                    IssuerCredentialsCapabilities.builder()
                            .credentialsType("LEARCredentialEmployee")
                            .validFor(null).claims(null).build()
            );
            when(trustFrameworkService.getTrustedIssuerListData("did:elsi:issuer")).thenReturn(caps);
            when(trustFrameworkService.getTrustedIssuerListData("VATIT-1234")).thenReturn(caps);

            Map<String, Object> vcHeaderMap = new HashMap<>();
            vcHeaderMap.put("x5c", List.of("base64Cert"));
            JWSHeader vcHeader = mock(JWSHeader.class);
            when(vcSignedJWT.getHeader()).thenReturn(vcHeader);
            when(vcHeader.toJSONObject()).thenReturn(vcHeaderMap);
            when(vcSignedJWT.serialize()).thenReturn(vcJwt);

            doNothing().when(certificateValidationService).extractAndVerifyCertificate(any(), eq(vcHeaderMap), eq("issuer"));
            doNothing().when(cryptographicBindingValidator).validateVpSignatureAndBinding(any(), any(), any());

            assertDoesNotThrow(() -> vpServiceImpl.verifyVerifiablePresentation(vpToken));
            verify(cryptographicBindingValidator).validateVpSignatureAndBinding(any(), any(), any());
        }
    }

    // --- Time window tests ---

    @Test
    void verifyVerifiablePresentation_expiredCredential_throwsCredentialExpiredException() throws Exception {
        String vpToken = "invalid-time-window.vp.jwt";
        String vcJwt = "invalid-time-window.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mockedSignedJWT = mockStatic(SignedJWT.class)) {
            mockedSignedJWT.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mockedSignedJWT.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            JWTClaimsSet vpClaimsSet = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaimsSet);
            when(vpClaimsSet.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            Payload payload = mock(Payload.class);
            when(jwtService.extractPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            GenericCredential credential = buildGenericCredential(
                    Instant.now().minus(2, ChronoUnit.DAYS),
                    Instant.now().minus(1, ChronoUnit.DAYS),
                    null, null, null);
            when(genericCredentialFactory.create(payload)).thenReturn(credential);

            assertThrows(CredentialExpiredException.class,
                    () -> vpServiceImpl.verifyVerifiablePresentation(vpToken));
        }
    }

    @Test
    void verifyVerifiablePresentation_notYetValid_throwsCredentialNotActiveException() throws Exception {
        String vpToken = "invalid-time-window.vp.jwt";
        String vcJwt = "invalid-time-window.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mockedSignedJWT = mockStatic(SignedJWT.class)) {
            mockedSignedJWT.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mockedSignedJWT.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            JWTClaimsSet vpClaimsSet = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaimsSet);
            when(vpClaimsSet.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            Payload payload = mock(Payload.class);
            when(jwtService.extractPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            GenericCredential credential = buildGenericCredential(
                    Instant.now().plus(1, ChronoUnit.DAYS),
                    Instant.now().plus(2, ChronoUnit.DAYS),
                    null, null, null);
            when(genericCredentialFactory.create(payload)).thenReturn(credential);

            assertThrows(CredentialNotActiveException.class,
                    () -> vpServiceImpl.verifyVerifiablePresentation(vpToken));
        }
    }

    // --- Revocation tests ---

    @Test
    void verifyVerifiablePresentation_statusListUnreachable_doesNotThrow() throws Exception {
        String vpToken = "valid.vp.jwt";
        String vcJwt = "valid.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mocked = mockStatic(SignedJWT.class)) {
            mocked.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mocked.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            JWTClaimsSet vpClaims = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaims);
            when(vpClaims.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
            when(vcSignedJWT.getJWTClaimsSet()).thenReturn(vcClaims);
            when(vcClaims.getIssuer()).thenReturn("did:elsi:VATES-FOO");

            Payload payload = mock(Payload.class);
            when(jwtService.extractPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            GenericCredential credential = buildGenericCredentialWithRevocation(
                    Instant.now().minus(1, ChronoUnit.MINUTES),
                    Instant.now().plus(5, ChronoUnit.MINUTES),
                    "VATES-FOO", null);
            when(genericCredentialFactory.create(payload)).thenReturn(credential);

            when(bitstringStatusListVerifier.supports("BitstringStatusListEntry")).thenReturn(true);
            when(bitstringStatusListVerifier.isRevoked(
                    "https://status-list.example.com/status/1", "42", "revocation"))
                    .thenThrow(new FailedCommunicationException("Connection refused"));

            List<IssuerCredentialsCapabilities> caps = List.of(
                    IssuerCredentialsCapabilities.builder()
                            .credentialsType("LEARCredentialEmployee")
                            .validFor(null).claims(null).build()
            );
            when(trustFrameworkService.getTrustedIssuerListData("did:elsi:VATES-FOO")).thenReturn(caps);

            JWSHeader vcHeader = mock(JWSHeader.class);
            when(vcSignedJWT.getHeader()).thenReturn(vcHeader);
            when(vcHeader.toJSONObject()).thenReturn(Map.of("x5c", List.of("base64Cert")));
            when(vcSignedJWT.serialize()).thenReturn(vcJwt);
            doNothing().when(certificateValidationService).extractAndVerifyCertificate(any(), anyMap(), anyString());
            doNothing().when(cryptographicBindingValidator).validateVpSignatureAndBinding(any(), any(), any());

            assertDoesNotThrow(() -> vpServiceImpl.verifyVerifiablePresentation(vpToken));
        }
    }

    @Test
    void verifyVerifiablePresentation_credentialConfirmedRevoked_throwsCredentialRevokedException() throws Exception {
        String vpToken = "valid.vp.jwt";
        String vcJwt = "valid.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mocked = mockStatic(SignedJWT.class)) {
            mocked.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mocked.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            JWTClaimsSet vpClaims = mock(JWTClaimsSet.class);
            when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaims);
            when(vpClaims.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

            Payload payload = mock(Payload.class);
            when(jwtService.extractPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

            GenericCredential credential = buildGenericCredentialWithRevocation(
                    Instant.now().minus(1, ChronoUnit.MINUTES),
                    Instant.now().plus(5, ChronoUnit.MINUTES),
                    null, null);
            when(genericCredentialFactory.create(payload)).thenReturn(credential);

            when(bitstringStatusListVerifier.supports("BitstringStatusListEntry")).thenReturn(true);
            when(bitstringStatusListVerifier.isRevoked(
                    "https://status-list.example.com/status/1", "42", "revocation"))
                    .thenReturn(true);

            assertThrows(CredentialRevokedException.class,
                    () -> vpServiceImpl.verifyVerifiablePresentation(vpToken));
        }
    }

    // --- Cryptographic binding tests ---

    @Test
    void verifyVerifiablePresentation_cryptographicBindingMismatch_throwsInvalidScopeException() throws Exception {
        String vpToken = "valid.vp.jwt";
        String vcJwt = "valid.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mocked = mockStatic(SignedJWT.class)) {
            mocked.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mocked.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            setupFullPipelineMocks(vpSignedJWT, vcSignedJWT, vcJwt);

            doThrow(new InvalidScopeException("Cryptographic binding mismatch"))
                    .when(cryptographicBindingValidator).validateVpSignatureAndBinding(any(), any(), any());

            assertThrows(InvalidScopeException.class,
                    () -> vpServiceImpl.verifyVerifiablePresentation(vpToken));
        }
    }

    @Test
    void verifyVerifiablePresentation_signatureVerificationFails_throwsRuntimeException() throws Exception {
        String vpToken = "valid.vp.jwt";
        String vcJwt = "valid.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mocked = mockStatic(SignedJWT.class)) {
            mocked.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mocked.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            setupFullPipelineMocks(vpSignedJWT, vcSignedJWT, vcJwt);

            doThrow(new RuntimeException("Signature verification failed"))
                    .when(cryptographicBindingValidator).validateVpSignatureAndBinding(any(), any(), any());

            RuntimeException ex = assertThrows(RuntimeException.class,
                    () -> vpServiceImpl.verifyVerifiablePresentation(vpToken));
            assertEquals("Signature verification failed", ex.getMessage());
        }
    }

    @Test
    void verifyVerifiablePresentation_holderDidCannotBeResolved_throwsInvalidScopeException() throws Exception {
        String vpToken = "valid.vp.jwt";
        String vcJwt = "valid.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mocked = mockStatic(SignedJWT.class)) {
            mocked.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mocked.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            setupFullPipelineMocks(vpSignedJWT, vcSignedJWT, vcJwt);

            doThrow(new InvalidScopeException("Cannot extract holder identity from VP"))
                    .when(cryptographicBindingValidator).validateVpSignatureAndBinding(any(), any(), any());

            assertThrows(InvalidScopeException.class,
                    () -> vpServiceImpl.verifyVerifiablePresentation(vpToken));
        }
    }

    @Test
    void verifyVerifiablePresentation_publicKeyRetrievalFails_throwsRuntimeException() throws Exception {
        String vpToken = "valid.vp.jwt";
        String vcJwt = "valid.vc.jwt";

        SignedJWT vpSignedJWT = mock(SignedJWT.class);
        SignedJWT vcSignedJWT = mock(SignedJWT.class);

        try (MockedStatic<SignedJWT> mocked = mockStatic(SignedJWT.class)) {
            mocked.when(() -> SignedJWT.parse(vpToken)).thenReturn(vpSignedJWT);
            mocked.when(() -> SignedJWT.parse(vcJwt)).thenReturn(vcSignedJWT);

            setupFullPipelineMocks(vpSignedJWT, vcSignedJWT, vcJwt);

            doThrow(new RuntimeException("Public key not found"))
                    .when(cryptographicBindingValidator).validateVpSignatureAndBinding(any(), any(), any());

            RuntimeException ex = assertThrows(RuntimeException.class,
                    () -> vpServiceImpl.verifyVerifiablePresentation(vpToken));
            assertEquals("Public key not found", ex.getMessage());
        }
    }

    // --- CryptographicBindingValidator reflection tests ---

    @Test
    void extractDidFromKidIssSub_validKidWithFragment_returnsDidWithoutFragment() throws Exception {
        CryptographicBindingValidator service = new CryptographicBindingValidator(null, null);
        Method method = CryptographicBindingValidator.class.getDeclaredMethod("extractDidFromKidIssSub", String.class, String.class, String.class);
        method.setAccessible(true);

        String result = (String) method.invoke(service, "did:example:12345#fragment", null, null);
        assertEquals("did:example:12345", result);
    }

    @Test
    void extractDidFromKidIssSub_validKidWithoutFragment_returnsKid() throws Exception {
        CryptographicBindingValidator service = new CryptographicBindingValidator(null, null);
        Method method = CryptographicBindingValidator.class.getDeclaredMethod("extractDidFromKidIssSub", String.class, String.class, String.class);
        method.setAccessible(true);

        String result = (String) method.invoke(service, "did:example:12345", null, null);
        assertEquals("did:example:12345", result);
    }

    @Test
    void extractDidFromKidIssSub_invalidKid_validIss_returnsIss() throws Exception {
        CryptographicBindingValidator service = new CryptographicBindingValidator(null, null);
        Method method = CryptographicBindingValidator.class.getDeclaredMethod("extractDidFromKidIssSub", String.class, String.class, String.class);
        method.setAccessible(true);

        String result = (String) method.invoke(service, "invalid-kid", "did:example:iss", null);
        assertEquals("did:example:iss", result);
    }

    @Test
    void extractDidFromKidIssSub_invalidKid_invalidIss_validSub_returnsSub() throws Exception {
        CryptographicBindingValidator service = new CryptographicBindingValidator(null, null);
        Method method = CryptographicBindingValidator.class.getDeclaredMethod("extractDidFromKidIssSub", String.class, String.class, String.class);
        method.setAccessible(true);

        String result = (String) method.invoke(service, "invalid-kid", "invalid-iss", "did:example:sub");
        assertEquals("did:example:sub", result);
    }

    @Test
    void extractDidFromKidIssSub_allInvalid_returnsNull() throws Exception {
        CryptographicBindingValidator service = new CryptographicBindingValidator(null, null);
        Method method = CryptographicBindingValidator.class.getDeclaredMethod("extractDidFromKidIssSub", String.class, String.class, String.class);
        method.setAccessible(true);

        String result = (String) method.invoke(service, "invalid-kid", "invalid-iss", "invalid-sub");
        assertNull(result);
    }

    // --- Helper methods ---

    /**
     * Sets up all mocks for a full VP pipeline that passes all steps up to (but not including) step 9.
     * Uses a GenericCredential with mandator path configured.
     */
    private void setupFullPipelineMocks(SignedJWT vpSignedJWT, SignedJWT vcSignedJWT, String vcJwt) throws Exception {
        JWTClaimsSet vpClaims = mock(JWTClaimsSet.class);
        when(vpSignedJWT.getJWTClaimsSet()).thenReturn(vpClaims);
        when(vpClaims.getClaim("vp")).thenReturn(Map.of("verifiableCredential", List.of(vcJwt)));

        JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
        when(vcSignedJWT.getJWTClaimsSet()).thenReturn(vcClaims);
        when(vcClaims.getIssuer()).thenReturn("did:elsi:VATES-FOO");

        Payload payload = mock(Payload.class);
        when(jwtService.extractPayloadFromSignedJWT(vcSignedJWT)).thenReturn(payload);

        GenericCredential credential = buildGenericCredential(
                Instant.now().minus(1, ChronoUnit.MINUTES),
                Instant.now().plus(5, ChronoUnit.MINUTES),
                "VATES-FOO",
                "credentialSubject.mandate.mandator.organizationIdentifier",
                null);
        when(genericCredentialFactory.create(payload)).thenReturn(credential);

        List<IssuerCredentialsCapabilities> caps = List.of(
                IssuerCredentialsCapabilities.builder()
                        .credentialsType("LEARCredentialEmployee")
                        .validFor(null).claims(null).build()
        );
        when(trustFrameworkService.getTrustedIssuerListData("did:elsi:VATES-FOO")).thenReturn(caps);
        when(trustFrameworkService.getTrustedIssuerListData("VATIT-1234")).thenReturn(caps);

        JWSHeader header = mock(JWSHeader.class);
        when(vcSignedJWT.getHeader()).thenReturn(header);
        when(header.toJSONObject()).thenReturn(Map.of("x5c", List.of("base64Cert")));
        when(vcSignedJWT.serialize()).thenReturn(vcJwt);
        doNothing().when(certificateValidationService).extractAndVerifyCertificate(any(), anyMap(), anyString());
    }

    /**
     * Builds a GenericCredential with no revocation configuration.
     */
    private GenericCredential buildGenericCredential(
            Instant validFrom, Instant validUntil,
            String issuerOrgId, String mandatorOrgIdPath,
            RevocationPaths revocationPaths) {

        ObjectNode root = MAPPER.createObjectNode();
        root.putArray("type").add("VerifiableCredential").add("LEARCredentialEmployee");
        root.putArray("@context")
                .add("https://www.w3.org/ns/credentials/v2")
                .add("https://trust-framework.dome-marketplace.eu/credentials/learcredentialemployee/v1");
        root.put("id", "urn:uuid:1234");
        root.put("validFrom", validFrom.toString());
        root.put("validUntil", validUntil.toString());

        // Issuer
        ObjectNode issuerNode = MAPPER.createObjectNode();
        issuerNode.put("organizationIdentifier", issuerOrgId != null ? issuerOrgId : "");
        root.set("issuer", issuerNode);

        // Mandator
        ObjectNode mandator = MAPPER.createObjectNode();
        mandator.put("organizationIdentifier", "VATIT-1234");
        ObjectNode mandate = MAPPER.createObjectNode();
        mandate.set("mandator", mandator);
        ObjectNode credentialSubject = MAPPER.createObjectNode();
        credentialSubject.set("mandate", mandate);
        root.set("credentialSubject", credentialSubject);

        ValidationPaths validationPaths = new ValidationPaths("validFrom", "validUntil", revocationPaths);

        SchemaProfile profile = new SchemaProfile(
                "LEARCredentialEmployee",
                "learcredential.employee",
                null,
                validationPaths,
                null,
                false,
                "issuer.organizationIdentifier",
                mandatorOrgIdPath
        );

        return new GenericCredential(
                root, profile, "LEARCredentialEmployee",
                List.of("VerifiableCredential", "LEARCredentialEmployee"),
                List.of("https://www.w3.org/ns/credentials/v2")
        );
    }

    /**
     * Builds a GenericCredential with revocation status configured.
     */
    private GenericCredential buildGenericCredentialWithRevocation(
            Instant validFrom, Instant validUntil,
            String issuerOrgId, String mandatorOrgIdPath) {

        RevocationPaths revocationPaths = new RevocationPaths(
                "credentialStatus.id",
                "credentialStatus.type",
                "credentialStatus.statusPurpose",
                "credentialStatus.statusListCredential",
                "credentialStatus.statusListIndex"
        );

        ObjectNode root = MAPPER.createObjectNode();
        root.putArray("type").add("VerifiableCredential").add("LEARCredentialEmployee");
        root.putArray("@context")
                .add("https://www.w3.org/ns/credentials/v2");
        root.put("id", "urn:uuid:cred-1");
        root.put("validFrom", validFrom.toString());
        root.put("validUntil", validUntil.toString());

        ObjectNode issuerNode = MAPPER.createObjectNode();
        issuerNode.put("organizationIdentifier", issuerOrgId != null ? issuerOrgId : "");
        root.set("issuer", issuerNode);

        ObjectNode mandator = MAPPER.createObjectNode();
        mandator.put("organizationIdentifier", "VATIT-1234");
        ObjectNode mandate = MAPPER.createObjectNode();
        mandate.set("mandator", mandator);
        ObjectNode credentialSubject = MAPPER.createObjectNode();
        credentialSubject.set("mandate", mandate);
        root.set("credentialSubject", credentialSubject);

        ObjectNode statusNode = MAPPER.createObjectNode();
        statusNode.put("id", "urn:uuid:status-1");
        statusNode.put("type", "BitstringStatusListEntry");
        statusNode.put("statusPurpose", "revocation");
        statusNode.put("statusListCredential", "https://status-list.example.com/status/1");
        statusNode.put("statusListIndex", "42");
        root.set("credentialStatus", statusNode);

        ValidationPaths validationPaths = new ValidationPaths("validFrom", "validUntil", revocationPaths);

        SchemaProfile profile = new SchemaProfile(
                "LEARCredentialEmployee",
                "learcredential.employee",
                null,
                validationPaths,
                null,
                false,
                "issuer.organizationIdentifier",
                mandatorOrgIdPath
        );

        return new GenericCredential(
                root, profile, "LEARCredentialEmployee",
                List.of("VerifiableCredential", "LEARCredentialEmployee"),
                List.of("https://www.w3.org/ns/credentials/v2")
        );
    }

    /**
     * Builds a VP JWT string containing a nested VC JWT that triggers payload extraction.
     * Uses a pre-built base64 VP token with an embedded dummy VC.
     */
    private String buildVpWithInnerVc() {
        return "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnpEbmFlblF6WEthVE5SNlYyaWZyY0VFU042VFR1WWpweWFmUGh0c1pZU3Y0VlJia3IiLCJuYmYiOjE3MTc0MzgwMDMsImlzcyI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImhvbGRlciI6ImRpZDprZXk6ekRuYWVuUXpYS2FUTlI2VjJpZnJjRUVTTjZUVHVZanB5YWZQaHRzWllTdjRWUmJrciIsImlkIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp6ZFdJaU9pSXhNak0wTlRZM09Ea3dJaXdpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVEUyTWpNNU1ESXlmUS5TZmxLeHdSSlNNZUtLRjJRVDRmd3BNZUpmMzZQT2s2eUpWX2FkUXNzdzVjIl19LCJleHAiOjE3MjAwMzAwMDMsImlhdCI6MTcxNzQzODAwMywianRpIjoiNDFhY2FkYTMtNjdiNC00OTRlLWE2ZTMtZTA5NjY0NDlmMjVkIn0._tIB_9fsQjZmJV2cgGDWtYXmps9fbLbMDtu8wZhIwC9u6I7RAaR4NK5WrnRC1TIVbQa06ZeneELxc_ktTkdhfA";
    }
}
