package es.in2.vcverifier.shared.crypto;

import es.in2.vcverifier.shared.domain.exception.PublicKeyDecodingException;
import es.in2.vcverifier.shared.domain.exception.UnsupportedDIDTypeException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class DIDServiceImplTest {

    @org.mockito.Spy
    private io.micrometer.core.instrument.MeterRegistry meterRegistry =
            new io.micrometer.core.instrument.simple.SimpleMeterRegistry();

    @InjectMocks
    private DIDServiceImpl didService;

    @Test
    void getPublicKeyFromValidDid_Success() {
        String validDid = "did:key:zDnaew7Cz5JbZtVGd93qxAjLB1qZEm1eXLPaWEr775R2BZkoY";
        PublicKey publicKey = didService.resolvePublicKeyFromDid(validDid);
        assertNotNull(publicKey);
    }

    @Test
    void resolvePublicKeyFromDid_UnsupportedDIDTypeException() {
        String invalidDid = "did:example:123456";

        UnsupportedDIDTypeException thrown = assertThrows(UnsupportedDIDTypeException.class, () -> {
            didService.resolvePublicKeyFromDid(invalidDid);
        });

        assertEquals("Unsupported DID type. Only did:key is supported for the moment.", thrown.getMessage());
    }

    @Test
    void resolvePublicKeyFromDid_PublicKeyDecodingException() {
        String invalidDid = "did:key:zInvalidPublicKey";

        PublicKeyDecodingException thrown = assertThrows(PublicKeyDecodingException.class, () -> {
            didService.resolvePublicKeyFromDid(invalidDid);
        });

        assertEquals("JWT signature verification failed.", thrown.getMessage());
    }
}
