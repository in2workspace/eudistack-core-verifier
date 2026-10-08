package es.in2.vcverifier.shared.crypto;

import com.nimbusds.jose.jwk.ECKey;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.domain.exception.ECKeyCreationException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Covers the x509_hash mode, client_id derivation and error paths of {@link CryptoComponent}. */
class CryptoComponentCertificateTest {

    private static final String PRIVATE_KEY_HEX = "73e509a7681d4a395b1ced75681c4dc4020dbab02da868512276dd766733d5b5";

    @TempDir
    Path dir;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private String privateKeyHex = PRIVATE_KEY_HEX;

    private BackendConfig identity(String certificatePath, String didKey) {
        BackendConfig config = mock(BackendConfig.class);
        when(config.hasIdentityConfigured()).thenReturn(true);
        when(config.getPrivateKey()).thenReturn(privateKeyHex);
        when(config.getCertificate()).thenReturn(certificatePath);
        when(config.getDidKey()).thenReturn(didKey);
        return config;
    }

    private X509Certificate writeCertificate(Path target) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        privateKeyHex = ((java.security.interfaces.ECPrivateKey) pair.getPrivate()).getS().toString(16);
        X500Principal subject = new X500Principal("CN=verifier");
        var builder = new JcaX509v3CertificateBuilder(subject, BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 60_000), new Date(System.currentTimeMillis() + 3_600_000),
                subject, pair.getPublic());
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256WithECDSA").setProvider("BC").build(pair.getPrivate())));
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        Files.writeString(target, pem);
        return cert;
    }

    @Test
    void getECKey_withCertificate_usesX509HashMode() throws Exception {
        Path certFile = dir.resolve("cert.pem");
        X509Certificate cert = writeCertificate(certFile);

        ECKey key = new CryptoComponent(identity(certFile.toString(), "did:key:zIgnored")).getECKey();

        assertEquals(1, key.getX509CertChain().size());
        byte[] expectedHash = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
        assertEquals(com.nimbusds.jose.util.Base64URL.encode(expectedHash), key.getX509CertSHA256Thumbprint());
        assertNotNull(key.getKeyID());
        assertTrue(!key.getKeyID().startsWith("did:key:"));
    }

    @Test
    void getClientId_withCertificate_returnsX509HashClientId() throws Exception {
        Path certFile = dir.resolve("cert.pem");
        writeCertificate(certFile);
        CryptoComponent component = new CryptoComponent(identity(certFile.toString(), null));

        assertTrue(component.getClientId().startsWith("x509_hash:"));
        assertEquals("x509_hash", component.getClientIdScheme());
    }

    @Test
    void getClientId_withoutCertificate_returnsDidKey() {
        CryptoComponent component = new CryptoComponent(identity(null, "did:key:zConfigured"));

        assertEquals("did:key:zConfigured", component.getClientId());
        assertEquals("did", component.getClientIdScheme());
    }

    @Test
    void getECKey_blankCertificatePath_fallsBackToDidKey() {
        ECKey key = new CryptoComponent(identity("  ", "did:key:zConfigured")).getECKey();

        assertEquals("did:key:zConfigured", key.getKeyID());
        assertNull(key.getX509CertChain());
    }

    @Test
    void getECKey_blankDidKey_derivesDidKey() {
        ECKey key = new CryptoComponent(identity(null, " ")).getECKey();

        assertTrue(key.getKeyID().startsWith("did:key:z"));
    }

    @Test
    void getECKey_missingCertificateFile_throwsECKeyCreationException() {
        var component = new CryptoComponent(identity(dir.resolve("absent.pem").toString(), null));

        assertThrows(ECKeyCreationException.class, component::getECKey);
    }

    @Test
    void getECKey_invalidCertificateContent_throwsECKeyCreationException() throws Exception {
        Path bad = dir.resolve("bad.pem");
        Files.writeString(bad, "not a certificate");

        assertThrows(ECKeyCreationException.class, new CryptoComponent(identity(bad.toString(), null))::getECKey);
    }

    @Test
    void getECKey_invalidPrivateKeyHex_throwsECKeyCreationException() {
        BackendConfig config = mock(BackendConfig.class);
        when(config.hasIdentityConfigured()).thenReturn(true);
        when(config.getPrivateKey()).thenReturn("not-hex");

        assertThrows(ECKeyCreationException.class, new CryptoComponent(config)::getECKey);
    }

    @Test
    void getClientIdScheme_ephemeralKey_isDid() {
        BackendConfig config = mock(BackendConfig.class);
        when(config.hasIdentityConfigured()).thenReturn(false);

        assertEquals("did", new CryptoComponent(config).getClientIdScheme());
    }
}
