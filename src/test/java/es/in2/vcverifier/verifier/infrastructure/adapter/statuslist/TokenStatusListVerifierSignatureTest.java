package es.in2.vcverifier.verifier.infrastructure.adapter.statuslist;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.crypto.DIDService;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;
import es.in2.vcverifier.verifier.domain.exception.CredentialException;
import es.in2.vcverifier.verifier.domain.exception.StatusListCredentialException;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Covers the signature verification (SEC-S5), claim validation and HTTP branches of
 * {@link TokenStatusListVerifier} with real signed Token Status List JWTs.
 */
class TokenStatusListVerifierSignatureTest {

    private static final String DID = "did:key:zStatusListIssuer";
    private static final String URL = "https://example.com/status/1";

    private final DIDService didService = mock(DIDService.class);
    private final SafeUrlValidator safeUrlValidator = mock(SafeUrlValidator.class);
    private final HttpClient httpClient = mock(HttpClient.class);
    private TokenStatusListVerifier verifier;
    private KeyPair ecKeyPair;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        verifier = new TokenStatusListVerifier(httpClient, new ObjectMapper(), safeUrlValidator, didService);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        ecKeyPair = generator.generateKeyPair();
    }

    // --- DID-based signature verification ---

    @Test
    void parse_didIssuer_validSignature_returnsData() throws Exception {
        when(didService.resolvePublicKeyFromDid(DID)).thenReturn(ecKeyPair.getPublic());
        String jwt = signEc(claims(DID, Map.of("bits", 1, "lst", lst(new byte[]{(byte) 0x80}))));

        var data = verifier.parseTokenStatusList(jwt);

        assertEquals(DID, data.issuer());
        assertEquals(1, data.bitsPerEntry());
        assertEquals((byte) 0x80, data.rawBytes()[0]);
    }

    @Test
    void parse_didIssuer_rsaKey_validSignature_returnsData() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair rsaPair = rsa.generateKeyPair();
        when(didService.resolvePublicKeyFromDid(DID)).thenReturn(rsaPair.getPublic());
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256),
                claims(DID, Map.of("bits", 1, "lst", lst(new byte[]{0x01}))));
        jwt.sign(new RSASSASigner(rsaPair.getPrivate()));

        var data = verifier.parseTokenStatusList(jwt.serialize());

        assertEquals(1, data.bitsPerEntry());
    }

    @Test
    void parse_didIssuer_wrongKey_throwsSignatureFailure() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        when(didService.resolvePublicKeyFromDid(DID)).thenReturn(generator.generateKeyPair().getPublic());
        String jwt = signEc(claims(DID, Map.of("bits", 1, "lst", lst(new byte[]{1}))));

        var ex = assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(jwt));

        assertTrue(ex.getMessage().contains("signature verification failed (DID"));
    }

    @Test
    void parse_didIssuer_unsupportedKeyType_throws() throws Exception {
        PublicKey dsaKey = KeyPairGenerator.getInstance("DSA").generateKeyPair().getPublic();
        when(didService.resolvePublicKeyFromDid(DID)).thenReturn(dsaKey);
        String jwt = signEc(claims(DID, Map.of("bits", 1, "lst", lst(new byte[]{1}))));

        var ex = assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(jwt));

        assertTrue(ex.getMessage().contains("unsupported key type"));
    }

    @Test
    void parse_didResolutionFails_wrapsInStatusListException() throws Exception {
        when(didService.resolvePublicKeyFromDid(DID)).thenThrow(new IllegalStateException("boom"));
        String jwt = signEc(claims(DID, Map.of("bits", 1, "lst", lst(new byte[]{1}))));

        var ex = assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(jwt));

        assertTrue(ex.getMessage().contains("signature verification error"));
    }

    @Test
    void parse_noX5cAndNonDidIssuer_throws() throws Exception {
        String jwt = signEc(claims("https://issuer.example", Map.of("bits", 1, "lst", lst(new byte[]{1}))));

        var ex = assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(jwt));

        assertTrue(ex.getMessage().contains("no x5c header and no DID issuer"));
    }

    @Test
    void parse_noIssuer_throws() throws Exception {
        String jwt = signEc(claims(null, Map.of("bits", 1, "lst", lst(new byte[]{1}))));

        assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(jwt));
    }

    @Test
    void parse_malformedJwt_throws() {
        assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList("not-a-jwt"));
    }

    // --- x5c-based signature verification ---

    @Test
    void parse_x5c_validSignature_returnsData() throws Exception {
        X509Certificate cert = selfSigned(ecKeyPair);
        String jwt = signEcWithX5c(claims(null, Map.of("bits", 2, "lst", lst(new byte[]{0x40}))), cert);

        var data = verifier.parseTokenStatusList(jwt);

        assertEquals(2, data.bitsPerEntry());
    }

    @Test
    void parse_x5c_signedWithOtherKey_throwsSignatureFailure() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        X509Certificate certOfOtherKey = selfSigned(generator.generateKeyPair());
        String jwt = signEcWithX5c(claims(null, Map.of("bits", 1, "lst", lst(new byte[]{1}))), certOfOtherKey);

        var ex = assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(jwt));

        assertTrue(ex.getMessage().contains("(x5c)"));
    }

    @Test
    void parse_x5c_garbageCertificate_wrapsInStatusListException() throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(List.of(Base64.encode(new byte[]{1, 2, 3}))).build(),
                claims(null, Map.of("bits", 1, "lst", lst(new byte[]{1}))));
        jwt.sign(new ECDSASigner((java.security.interfaces.ECPrivateKey) ecKeyPair.getPrivate()));

        String serialized = jwt.serialize();

        var ex = assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(serialized));

        assertTrue(ex.getMessage().contains("signature verification error"));
    }

    // --- status_list claim validation ---

    @Test
    void parse_missingStatusList_throws() throws Exception {
        stubDidKey();
        String jwt = signEc(new JWTClaimsSet.Builder().issuer(DID).build());

        assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(jwt));
    }

    @Test
    void parse_statusListNotObject_throws() throws Exception {
        stubDidKey();
        String jwt = signEc(new JWTClaimsSet.Builder().issuer(DID).claim("status_list", "text").build());

        assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(jwt));
    }

    @Test
    void parse_missingBits_throws() throws Exception {
        stubDidKey();
        String jwt = signEc(claims(DID, Map.of("lst", lst(new byte[]{1}))));

        var ex = assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(jwt));

        assertTrue(ex.getMessage().contains("'bits'"));
    }

    @Test
    void parse_bitsNotNumeric_throws() throws Exception {
        stubDidKey();
        String jwt = signEc(claims(DID, Map.of("bits", "one", "lst", lst(new byte[]{1}))));

        assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(jwt));
    }

    @Test
    void parse_missingLst_throws() throws Exception {
        stubDidKey();
        String jwt = signEc(claims(DID, Map.of("bits", 1)));

        var ex = assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(jwt));

        assertTrue(ex.getMessage().contains("'lst'"));
    }

    @Test
    void parse_blankLst_throws() throws Exception {
        stubDidKey();
        String jwt = signEc(claims(DID, Map.of("bits", 1, "lst", "  ")));

        assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(jwt));
    }

    @Test
    void parse_lstNotTextual_throws() throws Exception {
        stubDidKey();
        String jwt = signEc(claims(DID, Map.of("bits", 1, "lst", 42)));

        assertThrows(StatusListCredentialException.class, () -> verifier.parseTokenStatusList(jwt));
    }

    // --- isRevoked end to end ---

    @Test
    void isRevoked_revokedEntry_returnsTrue() throws Exception {
        stubDidKey();
        stubHttp(200, signEc(claims(DID, Map.of("bits", 1, "lst", lst(new byte[]{(byte) 0x80})))));

        assertTrue(verifier.isRevoked(URL, "0", "revocation"));
    }

    @Test
    void isRevoked_validEntry_returnsFalse() throws Exception {
        stubDidKey();
        stubHttp(200, signEc(claims(DID, Map.of("bits", 1, "lst", lst(new byte[]{(byte) 0x80})))));

        assertFalse(verifier.isRevoked(URL, "1", "revocation"));
    }

    @Test
    void isRevoked_indexBeyondList_throwsCredentialException() throws Exception {
        stubDidKey();
        stubHttp(200, signEc(claims(DID, Map.of("bits", 1, "lst", lst(new byte[]{0})))));

        assertThrows(CredentialException.class, () -> verifier.isRevoked(URL, "8", "revocation"));
    }

    @Test
    void isRevoked_httpServerError_throwsFailedCommunication() throws Exception {
        stubHttp(500, "");

        var ex = assertThrows(FailedCommunicationException.class, () -> verifier.isRevoked(URL, "0", "revocation"));

        assertTrue(ex.getMessage().contains("500"));
    }

    @Test
    void isRevoked_interrupted_throwsFailedCommunicationAndKeepsInterruptFlag() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new InterruptedException("stop"));

        try {
            assertThrows(FailedCommunicationException.class, () -> verifier.isRevoked(URL, "0", "revocation"));
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    // --- decompression edge case ---

    @Test
    void decodeLst_emptyGzipMagicTruncated_throws() {
        String truncatedGzip = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(new byte[]{0x1F, (byte) 0x8B, 0x08});

        assertThrows(StatusListCredentialException.class, () -> verifier.decodeLst(truncatedGzip));
    }

    // --- helpers ---

    private void stubDidKey() {
        when(didService.resolvePublicKeyFromDid(DID)).thenReturn(ecKeyPair.getPublic());
    }

    @SuppressWarnings("unchecked")
    private void stubHttp(int status, String body) throws Exception {
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.body()).thenReturn(body);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(response);
    }

    private static JWTClaimsSet claims(String issuer, Map<String, Object> statusList) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder().subject(URL).claim("status_list", statusList);
        if (issuer != null) {
            builder.issuer(issuer);
        }
        return builder.build();
    }

    private String signEc(JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
        jwt.sign(new ECDSASigner((java.security.interfaces.ECPrivateKey) ecKeyPair.getPrivate()));
        return jwt.serialize();
    }

    private String signEcWithX5c(JWTClaimsSet claims, X509Certificate cert) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(List.of(Base64.encode(cert.getEncoded()))).build(), claims);
        jwt.sign(new ECDSASigner((java.security.interfaces.ECPrivateKey) ecKeyPair.getPrivate()));
        return jwt.serialize();
    }

    private static String lst(byte[] raw) {
        Deflater deflater = new Deflater();
        deflater.setInput(raw);
        deflater.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[256];
        while (!deflater.finished()) {
            out.write(buffer, 0, deflater.deflate(buffer));
        }
        deflater.end();
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(out.toByteArray());
    }

    private static X509Certificate selfSigned(KeyPair pair) throws Exception {
        X500Principal subject = new X500Principal("CN=status-list-issuer");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithECDSA").setProvider("BC").build(pair.getPrivate());
        var builder = new JcaX509v3CertificateBuilder(subject, BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 60_000), new Date(System.currentTimeMillis() + 3_600_000),
                subject, pair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }
}
