package es.in2.vcverifier.verifier.infrastructure.adapter;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.crypto.DIDService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.exception.InvalidScopeException;
import es.in2.vcverifier.verifier.domain.exception.InvalidVPtokenException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CryptographicBindingValidatorTest {

    @Mock
    private JWTService jwtService;
    @Mock
    private DIDService didService;

    private CryptographicBindingValidator validator;

    @BeforeEach
    void setUp() {
        validator = new CryptographicBindingValidator(jwtService, didService);
    }

    // --- validateVpSignature: embedded JWK strategy ---

    @Test
    void validateVpSignature_embeddedJwk_verifiesAndReturnsKey() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
        SignedJWT vpJwt = mock(SignedJWT.class);
        JWSHeader header = mock(JWSHeader.class);

        when(vpJwt.getHeader()).thenReturn(header);
        when(header.getJWK()).thenReturn(ecKey);
        doNothing().when(jwtService).verifyJWTWithECKey(any(), any(ECPublicKey.class));

        ECPublicKey result = validator.validateVpSignature("vp.jwt.raw", vpJwt);

        assertNotNull(result);
        assertEquals(ecKey.toECPublicKey(), result);
        verify(jwtService).verifyJWTWithECKey(eq("vp.jwt.raw"), any(ECPublicKey.class));
        verifyNoInteractions(didService);
    }

    @Test
    void validateVpSignature_embeddedJwk_notEcKey_fallsThroughToDid() throws Exception {
        SignedJWT vpJwt = mock(SignedJWT.class);
        JWSHeader header = mock(JWSHeader.class);
        JWTClaimsSet claims = mock(JWTClaimsSet.class);

        when(vpJwt.getHeader()).thenReturn(header);
        when(header.getJWK()).thenReturn(null);
        when(header.getKeyID()).thenReturn("did:example:123");
        when(vpJwt.getJWTClaimsSet()).thenReturn(claims);
        when(claims.getIssuer()).thenReturn(null);
        when(claims.getSubject()).thenReturn(null);

        ECKey resolvedKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPublicKey resolvedPublicKey = resolvedKey.toECPublicKey();
        when(didService.resolvePublicKeyFromDid("did:example:123")).thenReturn(resolvedPublicKey);
        doNothing().when(jwtService).verifyJWTWithECKey(any(), eq(resolvedPublicKey));

        ECPublicKey result = validator.validateVpSignature("vp.jwt.raw", vpJwt);

        assertNotNull(result);
        assertEquals(resolvedPublicKey, result);
        verify(didService).resolvePublicKeyFromDid("did:example:123");
    }

    // --- validateVpSignature: DID strategy ---

    @Test
    void validateVpSignature_didFromKid_verifiesAndReturnsKey() throws Exception {
        SignedJWT vpJwt = mock(SignedJWT.class);
        JWSHeader header = mock(JWSHeader.class);
        JWTClaimsSet claims = mock(JWTClaimsSet.class);

        when(vpJwt.getHeader()).thenReturn(header);
        when(header.getJWK()).thenReturn(null);
        when(header.getKeyID()).thenReturn("did:key:zABC#key-1");
        when(vpJwt.getJWTClaimsSet()).thenReturn(claims);
        when(claims.getIssuer()).thenReturn(null);
        when(claims.getSubject()).thenReturn(null);

        ECKey resolvedKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPublicKey resolvedPublicKey = resolvedKey.toECPublicKey();
        when(didService.resolvePublicKeyFromDid("did:key:zABC")).thenReturn(resolvedPublicKey);
        doNothing().when(jwtService).verifyJWTWithECKey(any(), eq(resolvedPublicKey));

        ECPublicKey result = validator.validateVpSignature("vp.jwt.raw", vpJwt);

        assertEquals(resolvedPublicKey, result);
        verify(didService).resolvePublicKeyFromDid("did:key:zABC");
    }

    @Test
    void validateVpSignature_didFromIss_verifiesAndReturnsKey() throws Exception {
        SignedJWT vpJwt = mock(SignedJWT.class);
        JWSHeader header = mock(JWSHeader.class);
        JWTClaimsSet claims = mock(JWTClaimsSet.class);

        when(vpJwt.getHeader()).thenReturn(header);
        when(header.getJWK()).thenReturn(null);
        when(header.getKeyID()).thenReturn("not-a-did");
        when(vpJwt.getJWTClaimsSet()).thenReturn(claims);
        when(claims.getIssuer()).thenReturn("did:web:issuer.example");
        when(claims.getSubject()).thenReturn(null);

        ECKey resolvedKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPublicKey resolvedPublicKey = resolvedKey.toECPublicKey();
        when(didService.resolvePublicKeyFromDid("did:web:issuer.example")).thenReturn(resolvedPublicKey);
        doNothing().when(jwtService).verifyJWTWithECKey(any(), eq(resolvedPublicKey));

        ECPublicKey result = validator.validateVpSignature("vp.jwt.raw", vpJwt);

        assertEquals(resolvedPublicKey, result);
        verify(didService).resolvePublicKeyFromDid("did:web:issuer.example");
    }

    @Test
    void validateVpSignature_didFromSub_verifiesAndReturnsKey() throws Exception {
        SignedJWT vpJwt = mock(SignedJWT.class);
        JWSHeader header = mock(JWSHeader.class);
        JWTClaimsSet claims = mock(JWTClaimsSet.class);

        when(vpJwt.getHeader()).thenReturn(header);
        when(header.getJWK()).thenReturn(null);
        when(header.getKeyID()).thenReturn("not-a-did");
        when(vpJwt.getJWTClaimsSet()).thenReturn(claims);
        when(claims.getIssuer()).thenReturn("https://example.com");
        when(claims.getSubject()).thenReturn("did:key:zSub");

        ECKey resolvedKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPublicKey resolvedPublicKey = resolvedKey.toECPublicKey();
        when(didService.resolvePublicKeyFromDid("did:key:zSub")).thenReturn(resolvedPublicKey);
        doNothing().when(jwtService).verifyJWTWithECKey(any(), eq(resolvedPublicKey));

        ECPublicKey result = validator.validateVpSignature("vp.jwt.raw", vpJwt);

        assertEquals(resolvedPublicKey, result);
        verify(didService).resolvePublicKeyFromDid("did:key:zSub");
    }

    @Test
    void validateVpSignature_didResolvesToNonEcKey_throwsInvalidVPtokenException() throws Exception {
        SignedJWT vpJwt = mock(SignedJWT.class);
        JWSHeader header = mock(JWSHeader.class);
        JWTClaimsSet claims = mock(JWTClaimsSet.class);

        when(vpJwt.getHeader()).thenReturn(header);
        when(header.getJWK()).thenReturn(null);
        when(header.getKeyID()).thenReturn("did:key:zABC");
        when(vpJwt.getJWTClaimsSet()).thenReturn(claims);
        when(claims.getIssuer()).thenReturn(null);
        when(claims.getSubject()).thenReturn(null);

        PublicKey nonEcKey = mock(PublicKey.class);
        when(didService.resolvePublicKeyFromDid("did:key:zABC")).thenReturn(nonEcKey);

        InvalidVPtokenException exception = assertThrows(
                InvalidVPtokenException.class,
                () -> validator.validateVpSignature("vp.jwt.raw", vpJwt)
        );

        assertEquals("Resolved DID public key is not an EC public key", exception.getMessage());
        verify(didService).resolvePublicKeyFromDid("did:key:zABC");
        verifyNoInteractions(jwtService);
    }

    @Test
    void validateVpSignature_noDid_throwsInvalidScopeException() throws Exception {
        SignedJWT vpJwt = mock(SignedJWT.class);
        JWSHeader header = mock(JWSHeader.class);
        JWTClaimsSet claims = mock(JWTClaimsSet.class);

        when(vpJwt.getHeader()).thenReturn(header);
        when(header.getJWK()).thenReturn(null);
        when(header.getKeyID()).thenReturn("not-a-did");
        when(vpJwt.getJWTClaimsSet()).thenReturn(claims);
        when(claims.getIssuer()).thenReturn("https://example.com");
        when(claims.getSubject()).thenReturn("not-a-did");

        assertThrows(InvalidScopeException.class,
                () -> validator.validateVpSignature("vp.jwt.raw", vpJwt));
        verifyNoInteractions(didService, jwtService);
    }

    @Test
    void validateVpSignature_claimsReadFails_throwsInvalidVPtokenException() throws Exception {
        SignedJWT vpJwt = mock(SignedJWT.class);
        JWSHeader header = mock(JWSHeader.class);

        when(vpJwt.getHeader()).thenReturn(header);
        when(header.getJWK()).thenReturn(null);
        when(header.getKeyID()).thenReturn("not-a-did");
        when(vpJwt.getJWTClaimsSet()).thenThrow(new RuntimeException("parse error"));

        assertThrows(InvalidVPtokenException.class,
                () -> validator.validateVpSignature("vp.jwt.raw", vpJwt));
    }

    // --- validateCryptographicBinding ---

    @Test
    void validateCryptographicBinding_matchingThumbprints_passes() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPublicKey vpSignerKey = ecKey.toECPublicKey();

        SignedJWT vcJwt = mock(SignedJWT.class);
        JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
        when(vcJwt.getJWTClaimsSet()).thenReturn(vcClaims);
        when(vcClaims.getClaim("cnf")).thenReturn(Map.of("jwk", ecKey.toPublicJWK().toJSONObject()));

        assertDoesNotThrow(() -> validator.validateCryptographicBinding(vpSignerKey, vcJwt));
    }

    @Test
    void validateCryptographicBinding_mismatchedThumbprints_throwsInvalidScopeException() throws Exception {
        ECKey key1 = new ECKeyGenerator(Curve.P_256).generate();
        ECKey key2 = new ECKeyGenerator(Curve.P_256).generate();
        ECPublicKey vpSignerKey = key1.toECPublicKey();

        SignedJWT vcJwt = mock(SignedJWT.class);
        JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
        when(vcJwt.getJWTClaimsSet()).thenReturn(vcClaims);
        when(vcClaims.getClaim("cnf")).thenReturn(Map.of("jwk", key2.toPublicJWK().toJSONObject()));

        assertThrows(InvalidScopeException.class,
                () -> validator.validateCryptographicBinding(vpSignerKey, vcJwt));
    }

    @Test
    void validateCryptographicBinding_missingCnfJwk_throwsInvalidScopeException() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPublicKey vpSignerKey = ecKey.toECPublicKey();

        SignedJWT vcJwt = mock(SignedJWT.class);
        JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
        when(vcJwt.getJWTClaimsSet()).thenReturn(vcClaims);
        when(vcClaims.getClaim("cnf")).thenReturn(null);

        assertThrows(InvalidScopeException.class,
                () -> validator.validateCryptographicBinding(vpSignerKey, vcJwt));
    }

    @Test
    void validateCryptographicBinding_nullVpSignerKey_throwsInvalidScopeException() {
        // vpSignerKey null-check fires before any claim extraction
        SignedJWT vcJwt = mock(SignedJWT.class);

        assertThrows(InvalidScopeException.class,
                () -> validator.validateCryptographicBinding(null, vcJwt));

        verifyNoInteractions(vcJwt);
    }

    @Test
    void validateCryptographicBinding_cnfKid_resolvesAndValidates() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPublicKey vpSignerKey = holderKey.toECPublicKey();
        ECPublicKey resolvedKey = holderKey.toECPublicKey();

        SignedJWT vcJwt = mock(SignedJWT.class);
        JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
        when(vcJwt.getJWTClaimsSet()).thenReturn(vcClaims);
        // cnf.jwk is absent; cnf.kid is present — strategy 2 succeeds, no further claims needed
        when(vcClaims.getClaim("cnf")).thenReturn(Map.of("kid", "did:key:zABC#key-1"));
        when(didService.resolvePublicKeyFromDid("did:key:zABC")).thenReturn(resolvedKey);

        assertDoesNotThrow(() -> validator.validateCryptographicBinding(vpSignerKey, vcJwt));
        verify(didService).resolvePublicKeyFromDid("did:key:zABC");
    }

    @Test
    void validateCryptographicBinding_mandateeIdW3cFormat_resolvesAndValidates() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPublicKey vpSignerKey = holderKey.toECPublicKey();
        ECPublicKey resolvedKey = holderKey.toECPublicKey();

        SignedJWT vcJwt = mock(SignedJWT.class);
        JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
        when(vcJwt.getJWTClaimsSet()).thenReturn(vcClaims);
        // no cnf at all
        when(vcClaims.getClaim("cnf")).thenReturn(null);
        // no vc wrap (VCDM 2.0 — claims at root)
        when(vcClaims.getClaim("vc")).thenReturn(null);
        // credentialSubject.mandate.mandatee.id present
        Map<String, Object> mandatee = Map.of("id", "did:key:zHolder");
        Map<String, Object> mandate = Map.of("mandatee", mandatee);
        Map<String, Object> cs = Map.of("mandate", mandate);
        when(vcClaims.getClaim("credentialSubject")).thenReturn(cs);
        when(didService.resolvePublicKeyFromDid("did:key:zHolder")).thenReturn(resolvedKey);

        assertDoesNotThrow(() -> validator.validateCryptographicBinding(vpSignerKey, vcJwt));
        verify(didService).resolvePublicKeyFromDid("did:key:zHolder");
    }

    @Test
    void validateCryptographicBinding_mandateeIdSdJwtFlatFormat_resolvesAndValidates() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPublicKey vpSignerKey = holderKey.toECPublicKey();
        ECPublicKey resolvedKey = holderKey.toECPublicKey();

        SignedJWT vcJwt = mock(SignedJWT.class);
        JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
        when(vcJwt.getJWTClaimsSet()).thenReturn(vcClaims);
        // no cnf, no vc wrap, no credentialSubject
        when(vcClaims.getClaim("cnf")).thenReturn(null);
        when(vcClaims.getClaim("vc")).thenReturn(null);
        when(vcClaims.getClaim("credentialSubject")).thenReturn(null);
        // top-level mandate.mandatee.id
        Map<String, Object> mandatee = Map.of("id", "did:key:zFlat");
        Map<String, Object> mandate = Map.of("mandatee", mandatee);
        when(vcClaims.getClaim("mandate")).thenReturn(mandate);
        when(didService.resolvePublicKeyFromDid("did:key:zFlat")).thenReturn(resolvedKey);

        assertDoesNotThrow(() -> validator.validateCryptographicBinding(vpSignerKey, vcJwt));
        verify(didService).resolvePublicKeyFromDid("did:key:zFlat");
    }

    @Test
    void validateCryptographicBinding_allStrategiesMiss_throwsInvalidScopeException() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPublicKey vpSignerKey = ecKey.toECPublicKey();

        SignedJWT vcJwt = mock(SignedJWT.class);
        JWTClaimsSet vcClaims = mock(JWTClaimsSet.class);
        when(vcJwt.getJWTClaimsSet()).thenReturn(vcClaims);
        when(vcClaims.getClaim("cnf")).thenReturn(null);
        when(vcClaims.getClaim("credentialSubject")).thenReturn(null);
        when(vcClaims.getClaim("mandate")).thenReturn(null);

        assertThrows(InvalidScopeException.class,
                () -> validator.validateCryptographicBinding(vpSignerKey, vcJwt));
        verifyNoInteractions(didService);
    }

    // --- normalizeDid ---

    @Test
    void normalizeDid_didWithFragment_returnsBaseOnly() {
        assertEquals("did:key:zABC", validator.normalizeDid("did:key:zABC#key-1"));
    }

    @Test
    void normalizeDid_didWithoutFragment_returnsSame() {
        assertEquals("did:key:zABC", validator.normalizeDid("did:key:zABC"));
    }

    @Test
    void normalizeDid_nonDid_returnsSame() {
        assertEquals("https://example.com", validator.normalizeDid("https://example.com"));
    }

    @Test
    void normalizeDid_null_returnsNull() {
        assertNull(validator.normalizeDid(null));
    }
}
