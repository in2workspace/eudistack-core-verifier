package es.in2.vcverifier.shared.crypto;
import es.in2.vcverifier.shared.crypto.CertificateValidationServiceImpl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.domain.exception.CertificateChainValidationException;
import es.in2.vcverifier.shared.domain.exception.MismatchOrganizationIdentifierException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertificateValidationServiceImplTest {

    @Mock
    private CertificateChainValidator chainValidator;
    @Mock
    private BackendConfig backendConfig;

    private CertificateValidationServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new CertificateValidationServiceImpl(chainValidator, backendConfig);
    }

    // --- x5c header validation ---

    @Test
    void extractAndVerifyCertificate_x5cNotAList_throwsIllegalArgument() {
        Map<String, Object> header = Map.of("x5c", "not-a-list");
        assertThrows(IllegalArgumentException.class,
                () -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }

    @Test
    void extractAndVerifyCertificate_x5cMissing_throwsIllegalArgument() {
        Map<String, Object> header = Map.of();
        assertThrows(IllegalArgumentException.class,
                () -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }

    @Test
    void extractAndVerifyCertificate_x5cNull_throwsIllegalArgument() {
        Map<String, Object> header = new HashMap<>();
        header.put("x5c", null);
        assertThrows(IllegalArgumentException.class,
                () -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }

    @Test
    void extractAndVerifyCertificate_x5cEmptyList_throwsIllegalArgument() {
        Map<String, Object> header = Map.of("x5c", List.of());
        assertThrows(IllegalArgumentException.class,
                () -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }

    @Test
    void extractAndVerifyCertificate_x5cWithNonStringEntries_doesNotThrow() {
        // Non-string entries hit 'continue', loop finishes normally without finding a match.
        List<Object> x5c = new ArrayList<>();
        x5c.add(42);
        Map<String, Object> header = new HashMap<>();
        header.put("x5c", x5c);

        // The loop hits continue for non-string, finishes, and no exception is thrown
        // (no processCertificate returning null means the throw-after-process path is not reached)
        assertDoesNotThrow(() -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }

    @Test
    void extractAndVerifyCertificate_x5cWithInvalidBase64Cert_throwsMismatch() {
        // A string that decodes from base64 but is not a valid X.509 DER
        String invalidCert = Base64.getEncoder().encodeToString("this-is-not-a-certificate".getBytes());
        Map<String, Object> header = Map.of("x5c", List.of(invalidCert));

        // processCertificate catches CertificateException -> returns null -> throws MismatchOrganizationIdentifierException
        assertThrows(MismatchOrganizationIdentifierException.class,
                () -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }

    @Test
    void extractAndVerifyCertificate_x5cWithGarbageBase64_throwsMismatch() {
        // Valid base64 but garbage bytes, CertificateFactory will reject it
        String garbageCert = Base64.getEncoder().encodeToString(new byte[]{0x30, 0x00});
        Map<String, Object> header = Map.of("x5c", List.of(garbageCert));

        assertThrows(MismatchOrganizationIdentifierException.class,
                () -> service.extractAndVerifyCertificate("jwt", header, "orgId"));
    }

    // --- x5c chain validation ---

    @Test
    void extractAndVerifyCertificate_bypassFalse_chainValidatorCalled() throws Exception {
        String orgId = "VATES-W3C-TEST01";
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate cert = generateCertWithOrgId(keyPair, orgId);

        String certB64 = Base64.getEncoder().encodeToString(cert.getEncoded());
        Map<String, Object> vcHeader = new HashMap<>();
        vcHeader.put("x5c", List.of(certB64));

        String vcJwt = buildSignedJwt(keyPair, orgId);

        when(backendConfig.isX5cChainValidationBypassed()).thenReturn(false);

        service.extractAndVerifyCertificate(vcJwt, vcHeader, orgId);

        verify(chainValidator, times(1)).validateSelfContainedChain(any());
    }

    @Test
    void extractAndVerifyCertificate_bypassTrue_chainValidatorNotCalled() throws Exception {
        String orgId = "VATES-W3C-TEST02";
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate cert = generateCertWithOrgId(keyPair, orgId);

        String certB64 = Base64.getEncoder().encodeToString(cert.getEncoded());
        Map<String, Object> vcHeader = new HashMap<>();
        vcHeader.put("x5c", List.of(certB64));

        String vcJwt = buildSignedJwt(keyPair, orgId);

        when(backendConfig.isX5cChainValidationBypassed()).thenReturn(true);

        service.extractAndVerifyCertificate(vcJwt, vcHeader, orgId);

        verify(chainValidator, never()).validateSelfContainedChain(any());
    }

    @Test
    void extractAndVerifyCertificate_chainValidatorThrows_exceptionPropagates() throws Exception {
        String orgId = "VATES-W3C-TEST03";
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate cert = generateCertWithOrgId(keyPair, orgId);

        String certB64 = Base64.getEncoder().encodeToString(cert.getEncoded());
        Map<String, Object> vcHeader = new HashMap<>();
        vcHeader.put("x5c", List.of(certB64));

        String vcJwt = buildSignedJwt(keyPair, orgId);

        when(backendConfig.isX5cChainValidationBypassed()).thenReturn(false);
        doThrow(new CertificateChainValidationException("chain broken"))
                .when(chainValidator).validateSelfContainedChain(any());

        assertThrows(CertificateChainValidationException.class,
                () -> service.extractAndVerifyCertificate(vcJwt, vcHeader, orgId));
    }

    // --- helpers ---

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private static X509Certificate generateCertWithOrgId(KeyPair keyPair, String orgId) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        ASN1ObjectIdentifier orgIdOid = new ASN1ObjectIdentifier("2.5.4.97");
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN, "Test Seal");
        nameBuilder.addRDN(BCStyle.O, "Test Org");
        nameBuilder.addRDN(BCStyle.C, "ES");
        nameBuilder.addRDN(orgIdOid, orgId);
        X500Name x500Name = nameBuilder.build();

        Date notBefore = new Date(System.currentTimeMillis() - 86400_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86400_000L);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());

        X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
                x500Name, BigInteger.valueOf(System.currentTimeMillis()),
                notBefore, notAfter, x500Name, keyPair.getPublic()
        ).build(signer);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);
    }

    private static String buildSignedJwt(KeyPair keyPair, String issuer) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .claim("vc", Map.of("credentialSubject", Map.of()))
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner((RSAPrivateKey) keyPair.getPrivate()));
        return jwt.serialize();
    }
}
