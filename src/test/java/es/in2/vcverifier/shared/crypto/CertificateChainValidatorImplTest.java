package es.in2.vcverifier.shared.crypto;

import es.in2.vcverifier.shared.domain.exception.CertificateChainValidationException;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CertificateChainValidatorImplTest {

    // Pass-through stub: resolver returns its input unchanged so all existing tests
    // exercise only the PKIX validation path, not AIA fetching.
    private final AiaCertificateChainResolver passthroughResolver = chain -> chain;
    private final CertificateChainValidatorImpl validator = new CertificateChainValidatorImpl(passthroughResolver);

    @BeforeAll
    static void addBcProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ── Helper factories ────────────────────────────────────────────────────

    private static KeyPair generateEc() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(256);
        return gen.generateKeyPair();
    }

    /**
     * Builds an X.509 cert signed by {@code issuerKeyPair}.
     * When {@code issuerDn == subjectDn} and {@code issuerKeyPair == subjectKeyPair} it is self-signed.
     */
    private static X509Certificate buildCert(
            KeyPair subjectKeyPair, String subjectDn,
            KeyPair issuerKeyPair, String issuerDn,
            boolean isCA,
            Date notBefore, Date notAfter) throws Exception {

        X500Principal issuerPrincipal = new X500Principal(issuerDn);
        X500Principal subjectPrincipal = new X500Principal(subjectDn);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithECDSA")
                .setProvider("BC")
                .build(issuerKeyPair.getPrivate());

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerPrincipal,
                BigInteger.valueOf(System.nanoTime()),
                notBefore, notAfter,
                subjectPrincipal,
                subjectKeyPair.getPublic());

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));

        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    private static Date past() {
        return new Date(System.currentTimeMillis() - 86_400_000L);
    }

    private static Date future() {
        return new Date(System.currentTimeMillis() + 365L * 86_400_000L);
    }

    private static Date expired() {
        return new Date(System.currentTimeMillis() - 1000L);
    }

    // ── Tests ───────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Single self-signed certificate passes (degenerate case)")
    void validateChain_singleSelfSignedCert_succeeds() throws Exception {
        KeyPair kp = generateEc();
        X509Certificate selfSigned = buildCert(kp, "CN=Root", kp, "CN=Root", true, past(), future());

        assertDoesNotThrow(() -> validator.validateSelfContainedChain(List.of(selfSigned)));
    }

    @Test
    @DisplayName("Two-level chain (root CA → leaf) validates")
    void validateChain_twoLevelChain_succeeds() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();

        X509Certificate root = buildCert(rootKp, "CN=Root CA", rootKp, "CN=Root CA", true, past(), future());
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, past(), future());

        assertDoesNotThrow(() -> validator.validateSelfContainedChain(List.of(leaf, root)));
    }

    @Test
    @DisplayName("Three-level chain (root CA → intermediate CA → leaf) validates")
    void validateChain_threeLevelChain_succeeds() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair intKp = generateEc();
        KeyPair leafKp = generateEc();

        X509Certificate root = buildCert(rootKp, "CN=Root CA", rootKp, "CN=Root CA", true, past(), future());
        X509Certificate intermediate = buildCert(intKp, "CN=Intermediate CA", rootKp, "CN=Root CA", true, past(), future());
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", intKp, "CN=Intermediate CA", false, past(), future());

        assertDoesNotThrow(() -> validator.validateSelfContainedChain(List.of(leaf, intermediate, root)));
    }

    @Test
    @DisplayName("Chain where intermediate is signed by the wrong key throws")
    void validateChain_invalidIntermediateSignature_throws() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair rogue = generateEc();
        KeyPair leafKp = generateEc();

        X509Certificate root = buildCert(rootKp, "CN=Root CA", rootKp, "CN=Root CA", true, past(), future());
        // intermediate signed by rogue key instead of root
        X509Certificate intermediate = buildCert(rogue, "CN=Intermediate CA", rogue, "CN=Root CA", true, past(), future());
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rogue, "CN=Intermediate CA", false, past(), future());

        assertThrows(CertificateChainValidationException.class,
                () -> validator.validateSelfContainedChain(List.of(leaf, intermediate, root)));
    }

    @Test
    @DisplayName("Leaf cert that is expired throws")
    void validateChain_expiredLeaf_throws() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();

        X509Certificate root = buildCert(rootKp, "CN=Root CA", rootKp, "CN=Root CA", true, past(), future());
        X509Certificate expiredLeaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false,
                new Date(System.currentTimeMillis() - 2_000_000L), expired());

        assertThrows(CertificateChainValidationException.class,
                () -> validator.validateSelfContainedChain(List.of(expiredLeaf, root)));
    }

    @Test
    @DisplayName("Chain whose top cert is not self-signed is accepted unpinned (regression: HAIP §6.1 forbids issuers from including the root)")
    void validateChain_topNotSelfSigned_acceptedUnpinned() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair someOtherKp = generateEc();
        KeyPair leafKp = generateEc();

        // Top cert is signed by someOtherKp, not by itself — not self-signed, but the leaf's
        // signature still verifies against its public key, so it's still a valid anchor.
        X509Certificate notSelfSigned = buildCert(rootKp, "CN=Root CA", someOtherKp, "CN=Other CA", true, past(), future());
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, past(), future());

        assertDoesNotThrow(() -> validator.validateSelfContainedChain(List.of(leaf, notSelfSigned)));
    }

    @Test
    @DisplayName("Two-cert chain with no root at all (issuer stopped including it, HAIP §6.1) validates")
    void validateChain_noRootAtAll_succeeds() throws Exception {
        KeyPair caKp = generateEc();
        KeyPair someOtherKp = generateEc();
        KeyPair leafKp = generateEc();

        // Intermediate CA cert, signed by a throwaway "other" key rather than itself — never
        // self-signed and the resolver is a passthrough, so nothing chases it to a root either.
        // Matches the real shape of a conformant issuer that trimmed the root out of x5c.
        X509Certificate intermediate = buildCert(caKp, "CN=Intermediate CA", someOtherKp, "CN=Other", true, past(), future());
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", caKp, "CN=Intermediate CA", false, past(), future());

        assertDoesNotThrow(() -> validator.validateSelfContainedChain(List.of(leaf, intermediate)));
    }

    @Test
    @DisplayName("Single non-self-signed certificate (root trimmed down to just the leaf) validates on validity alone")
    void validateChain_singleNonSelfSignedLeaf_succeeds() throws Exception {
        KeyPair caKp = generateEc();
        KeyPair leafKp = generateEc();

        // Same shape as a 2-cert [leaf, root] response with the root trimmed - only the leaf
        // is left, and it is not self-signed (it was never meant to be).
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", caKp, "CN=Intermediate CA", false, past(), future());

        assertDoesNotThrow(() -> validator.validateSelfContainedChain(List.of(leaf)));
    }

    @Test
    @DisplayName("Empty chain throws")
    void validateChain_emptyList_throws() {
        assertThrows(CertificateChainValidationException.class,
                () -> validator.validateSelfContainedChain(List.of()));
    }

    @Test
    @DisplayName("Null chain throws")
    void validateChain_null_throws() {
        assertThrows(CertificateChainValidationException.class,
                () -> validator.validateSelfContainedChain(null));
    }

    @Test
    @DisplayName("Single expired self-signed certificate throws")
    void validateChain_singleExpiredSelfSigned_throws() throws Exception {
        KeyPair kp = generateEc();
        X509Certificate expired = buildCert(kp, "CN=Root", kp, "CN=Root", true,
                new Date(System.currentTimeMillis() - 2_000_000L), expired());

        assertThrows(CertificateChainValidationException.class,
                () -> validator.validateSelfContainedChain(List.of(expired)));
    }

    @Test
    @DisplayName("Resolver-completed chain (leaf-only input, resolver returns full chain) validates")
    void validateChain_resolverCompletesChain_succeeds() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();

        X509Certificate root = buildCert(rootKp, "CN=Root CA", rootKp, "CN=Root CA", true, past(), future());
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, past(), future());

        // Resolver fills in the root — simulates AIA chasing
        AiaCertificateChainResolver completingResolver = ignored -> List.of(leaf, root);
        CertificateChainValidatorImpl v = new CertificateChainValidatorImpl(completingResolver);

        assertDoesNotThrow(() -> v.validateSelfContainedChain(List.of(leaf)));
    }
}
