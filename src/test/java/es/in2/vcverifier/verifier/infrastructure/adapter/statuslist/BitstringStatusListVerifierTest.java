package es.in2.vcverifier.verifier.infrastructure.adapter.statuslist;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.crypto.CertificateValidationService;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;
import es.in2.vcverifier.verifier.domain.exception.CredentialException;
import es.in2.vcverifier.verifier.domain.model.StatusListCredentialData;
import es.in2.vcverifier.verifier.domain.service.StatusListCredentialService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BitstringStatusListVerifierTest {

    @InjectMocks
    private BitstringStatusListVerifier verifier;

    @Mock
    private CertificateValidationService certificateValidationService;

    @Mock
    private StatusListCredentialService statusListCredentialService;

    @Mock
    private HttpClient httpClient;

    @Mock
    private SafeUrlValidator safeUrlValidator;

    @Test
    void supports_bitstringStatusListEntry_returnsTrue() {
        assertTrue(verifier.supports("BitstringStatusListEntry"));
    }

    @Test
    void supports_otherType_returnsFalse() {
        assertFalse(verifier.supports("TokenStatusListEntry"));
        assertFalse(verifier.supports("unknown"));
    }

    // --- Input validation ---

    @Test
    void isRevoked_invalidIndex_throwsCredentialException() {
        assertThrows(CredentialException.class,
                () -> verifier.isRevoked("https://example.com/status", "not-a-number", "revocation"));
    }

    @Test
    void isRevoked_negativeIndex_throwsCredentialException() {
        assertThrows(CredentialException.class,
                () -> verifier.isRevoked("https://example.com/status", "-1", "revocation"));
    }

    // --- HTTP failures ---

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_httpReturns404_throwsFailedCommunication() throws Exception {
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(404);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThrows(FailedCommunicationException.class,
                () -> verifier.isRevoked("https://example.com/status", "0", "revocation"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_httpReturns500_throwsFailedCommunication() throws Exception {
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(500);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThrows(FailedCommunicationException.class,
                () -> verifier.isRevoked("https://example.com/status", "0", "revocation"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_httpThrowsIOException_throwsFailedCommunication() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("connection refused"));

        assertThrows(FailedCommunicationException.class,
                () -> verifier.isRevoked("https://example.com/status", "0", "revocation"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_httpThrowsInterruptedException_throwsFailedCommunication() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new InterruptedException("interrupted"));

        assertThrows(FailedCommunicationException.class,
                () -> verifier.isRevoked("https://example.com/status", "0", "revocation"));
    }

    // --- JWT parse failure ---

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_invalidJwt_throwsCredentialException() throws Exception {
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn("not-a-jwt");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThrows(CredentialException.class,
                () -> verifier.isRevoked("https://example.com/status", "0", "revocation"));
    }

    // --- Index out of range ---

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_indexOutOfRange_throwsCredentialException() throws Exception {
        String jwtString = buildMinimalJwtString("did:elsi:VATES-12345");

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(jwtString);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        doNothing().when(certificateValidationService)
                .extractAndVerifyCertificate(any(), any(), any());

        byte[] rawBytes = new byte[]{(byte) 0xFF};
        StatusListCredentialData statusData = new StatusListCredentialData(
                "did:elsi:VATES-12345", "revocation", rawBytes);

        when(statusListCredentialService.parse(any(SignedJWT.class))).thenReturn(statusData);
        doNothing().when(statusListCredentialService).validateStatusPurposeMatches(any(), any());
        when(statusListCredentialService.maxBits(any())).thenReturn(8);

        assertThrows(CredentialException.class,
                () -> verifier.isRevoked("https://example.com/status", "100", "revocation"));
    }

    // --- Happy path: revoked ---

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_bitIsSet_returnsTrue() throws Exception {
        String jwtString = buildMinimalJwtString("did:elsi:VATES-12345");

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(jwtString);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        doNothing().when(certificateValidationService)
                .extractAndVerifyCertificate(any(), any(), any());

        byte[] rawBytes = new byte[]{(byte) 0xFF};
        StatusListCredentialData statusData = new StatusListCredentialData(
                "did:elsi:VATES-12345", "revocation", rawBytes);

        when(statusListCredentialService.parse(any(SignedJWT.class))).thenReturn(statusData);
        doNothing().when(statusListCredentialService).validateStatusPurposeMatches(any(), any());
        when(statusListCredentialService.maxBits(any())).thenReturn(8);
        when(statusListCredentialService.isBitSet(any(), eq(3))).thenReturn(true);

        boolean result = verifier.isRevoked("https://example.com/status", "3", "revocation");

        assertTrue(result);
    }

    // --- Happy path: not revoked ---

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_bitNotSet_returnsFalse() throws Exception {
        String jwtString = buildMinimalJwtString("did:elsi:VATES-12345");

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(jwtString);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        doNothing().when(certificateValidationService)
                .extractAndVerifyCertificate(any(), any(), any());

        byte[] rawBytes = new byte[]{0x00};
        StatusListCredentialData statusData = new StatusListCredentialData(
                "did:elsi:VATES-12345", "revocation", rawBytes);

        when(statusListCredentialService.parse(any(SignedJWT.class))).thenReturn(statusData);
        doNothing().when(statusListCredentialService).validateStatusPurposeMatches(any(), any());
        when(statusListCredentialService.maxBits(any())).thenReturn(8);
        when(statusListCredentialService.isBitSet(any(), eq(3))).thenReturn(false);

        boolean result = verifier.isRevoked("https://example.com/status", "3", "revocation");

        assertFalse(result);
    }

    // --- Missing issuer in JWT ---

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_missingIssuerClaim_throwsCredentialException() throws Exception {
        String jwtString = buildMinimalJwtString(null);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(jwtString);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThrows(CredentialException.class,
                () -> verifier.isRevoked("https://example.com/status", "0", "revocation"));
    }

    // --- Unsupported issuer DID ---

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_unsupportedIssuerDid_throwsCredentialException() throws Exception {
        String jwtString = buildMinimalJwtString("did:key:z123abc");

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(jwtString);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThrows(CredentialException.class,
                () -> verifier.isRevoked("https://example.com/status", "0", "revocation"));
    }

    // --- Helper ---

    private String buildMinimalJwtString(String issuerDid) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
            if (issuerDid != null) {
                claimsBuilder.claim("issuer", issuerDid);
            }
            JWSObject jwsObject = new JWSObject(header, new Payload(claimsBuilder.build().toJSONObject()));
            String headerB64 = jwsObject.getHeader().toBase64URL().toString();
            String payloadB64 = jwsObject.getPayload().toBase64URL().toString();
            String sigB64 = "dummysig";
            return headerB64 + "." + payloadB64 + "." + sigB64;
        } catch (Exception e) {
            throw new RuntimeException("Failed to build test JWT", e);
        }
    }
}
