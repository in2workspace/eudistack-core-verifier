package es.in2.vcverifier.verifier.infrastructure.adapter.statuslist;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;
import es.in2.vcverifier.verifier.domain.exception.CredentialException;
import es.in2.vcverifier.verifier.domain.exception.StatusListCredentialException;
import es.in2.vcverifier.verifier.domain.model.TokenStatusListData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenStatusListVerifierTest {

    @InjectMocks
    private TokenStatusListVerifier verifier;

    @Mock
    private HttpClient httpClient;

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private SafeUrlValidator safeUrlValidator;

    @Test
    void supports_tokenStatusListEntry_returnsTrue() {
        assertTrue(verifier.supports("TokenStatusListEntry"));
    }

    @Test
    void supports_otherType_returnsFalse() {
        assertFalse(verifier.supports("BitstringStatusListEntry"));
        assertFalse(verifier.supports("unknown"));
    }

    // --- Input validation ---

    @Test
    void isRevoked_invalidIndex_throwsCredentialException() {
        assertThrows(CredentialException.class,
                () -> verifier.isRevoked("https://example.com/status", "abc", "revocation"));
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
    void isRevoked_httpThrowsIOException_throwsFailedCommunication() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("connection refused"));

        assertThrows(FailedCommunicationException.class,
                () -> verifier.isRevoked("https://example.com/status", "0", "revocation"));
    }

    // --- isStatusSet: 1-bit entries ---

    @Test
    void isStatusSet_1bit_bitSet_returnsTrue() {
        // byte 0b10000000 = bit 0 is set (MSB-first)
        byte[] rawBytes = new byte[]{(byte) 0x80};
        assertTrue(verifier.isStatusSet(rawBytes, 0, 1));
    }

    @Test
    void isStatusSet_1bit_bitNotSet_returnsFalse() {
        byte[] rawBytes = new byte[]{0x00};
        assertFalse(verifier.isStatusSet(rawBytes, 0, 1));
    }

    @Test
    void isStatusSet_1bit_secondBit_returnsTrue() {
        // byte 0b01000000 = bit 1 is set
        byte[] rawBytes = new byte[]{0x40};
        assertTrue(verifier.isStatusSet(rawBytes, 1, 1));
    }

    @Test
    void isStatusSet_1bit_lastBitInByte_returnsTrue() {
        // byte 0b00000001 = bit 7 is set
        byte[] rawBytes = new byte[]{0x01};
        assertTrue(verifier.isStatusSet(rawBytes, 7, 1));
    }

    // --- isStatusSet: 2-bit entries ---

    @Test
    void isStatusSet_2bits_nonZeroValue_returnsTrue() {
        // byte 0b01000000 = entry 0 has value 01 (bits 0-1 from MSB)
        byte[] rawBytes = new byte[]{0x40};
        assertTrue(verifier.isStatusSet(rawBytes, 0, 2));
    }

    @Test
    void isStatusSet_2bits_zeroValue_returnsFalse() {
        // byte 0b00110000 = entry 0 has value 00, entry 1 has value 11
        byte[] rawBytes = new byte[]{0x30};
        assertFalse(verifier.isStatusSet(rawBytes, 0, 2));
    }

    // --- isStatusSet: error cases ---

    @Test
    void isStatusSet_nullBytes_throwsException() {
        assertThrows(StatusListCredentialException.class,
                () -> verifier.isStatusSet(null, 0, 1));
    }

    @Test
    void isStatusSet_negativeIndex_throwsException() {
        assertThrows(StatusListCredentialException.class,
                () -> verifier.isStatusSet(new byte[]{0x00}, -1, 1));
    }

    @Test
    void isStatusSet_indexOutOfRange_throwsException() {
        assertThrows(StatusListCredentialException.class,
                () -> verifier.isStatusSet(new byte[]{0x00}, 8, 1));
    }

    // --- TokenStatusListData model ---

    @Test
    void tokenStatusListData_rejectNullRawBytes() {
        assertThrows(NullPointerException.class,
                () -> new TokenStatusListData("issuer", 1, null));
    }

    @Test
    void tokenStatusListData_rejectZeroBitsPerEntry() {
        assertThrows(IllegalArgumentException.class,
                () -> new TokenStatusListData("issuer", 0, new byte[]{1}));
    }

    @Test
    void tokenStatusListData_defensiveCopy() {
        byte[] input = new byte[]{1, 2, 3};
        TokenStatusListData data = new TokenStatusListData("issuer", 1, input);
        input[0] = 99;
        assertEquals(1, data.rawBytes()[0]);
    }
}
