package es.in2.vcverifier.shared.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.ThumbprintURI;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import es.in2.vcverifier.shared.config.VerifierConfig;
import es.in2.vcverifier.shared.domain.exception.ECKeyCreationException;
import io.github.novacrypto.base58.Base58;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class CryptoComponent {

    private final VerifierConfig verifierConfig;

    @Bean
    public ECKey getECKey() {
        if (verifierConfig.hasIdentityConfigured()) {
            log.info("Building EC key from configured private key");
            return buildEcKeyFromPrivateKey();
        }
        log.warn("No private key configured — generating ephemeral P-256 key pair. "
                + "This is suitable for development only. "
                + "Configure verifier.backend.identity.privateKey for production.");
        return generateEphemeralEcKey();
    }

    /**
     * Returns the client_id for OID4VP authorization requests.
     * When a certificate is configured, returns "x509_hash:&lt;base64url(sha256(DER(cert)))&gt;".
     * Otherwise, falls back to the ECKey's keyID (did:key).
     */
    public String getClientId() {
        ECKey ecKey = getECKey();
        Base64URL certHash = ecKey.getX509CertSHA256Thumbprint();
        if (certHash != null) {
            return "x509_hash:" + certHash;
        }
        return ecKey.getKeyID();
    }

    /**
     * Returns the client_id_scheme for OID4VP authorization requests.
     * "x509_hash" when a certificate is configured, "did" otherwise.
     */
    public String getClientIdScheme() {
        ECKey ecKey = getECKey();
        if (ecKey.getX509CertChain() != null && !ecKey.getX509CertChain().isEmpty()) {
            return "x509_hash";
        }
        return "did";
    }

    private ECKey buildEcKeyFromPrivateKey() {
        try {
            BigInteger privateKeyInt = new BigInteger(verifierConfig.getPrivateKey(), 16);
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());

            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKeyInt, ecSpec);
            ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);

            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecSpec.getG().multiply(privateKeyInt), ecSpec);
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);

            ECKey.Builder builder = new ECKey.Builder(Curve.P_256, publicKey)
                    .privateKey(privateKey)
                    .keyUse(KeyUse.SIGNATURE);

            // If certificate is configured, use x509_hash mode
            String certPath = verifierConfig.getCertificate();
            if (certPath != null && !certPath.isBlank()) {
                X509Certificate cert = loadCertificate(certPath);
                List<Base64> x5c = List.of(Base64.encode(cert.getEncoded()));
                Base64URL certThumbprint = computeX509SHA256Thumbprint(cert);
                String kid = computeJwkThumbprint(builder.build());

                builder.x509CertChain(x5c)
                       .x509CertSHA256Thumbprint(certThumbprint)
                       .keyID(kid);

                log.info("Configured x509_hash mode. client_id=x509_hash:{}, kid={}", certThumbprint, kid);
            } else {
                // Legacy: did:key
                String didKey = verifierConfig.getDidKey();
                if (didKey == null || didKey.isBlank()) {
                    didKey = deriveDidKey(publicKey);
                    log.info("Derived did:key from configured private key: {}", didKey);
                }
                builder.keyID(didKey);
            }

            return builder.build();
        } catch (Exception e) {
            throw new ECKeyCreationException("Error creating JWK source for secp256r1: " + e);
        }
    }

    private ECKey generateEphemeralEcKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
            var keyPair = keyPairGenerator.generateKeyPair();

            ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

            String didKey = deriveDidKey(publicKey);
            log.warn("Generated ephemeral P-256 key. did:key:{}", didKey);

            return new ECKey.Builder(Curve.P_256, publicKey)
                    .privateKey(privateKey)
                    .keyID(didKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .build();
        } catch (Exception e) {
            throw new ECKeyCreationException("Error generating ephemeral P-256 key pair: " + e);
        }
    }

    private static X509Certificate loadCertificate(String pemPath) {
        try {
            Path path = Path.of(pemPath);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            try (InputStream is = Files.newInputStream(path)) {
                return (X509Certificate) cf.generateCertificate(is);
            }
        } catch (IOException | java.security.cert.CertificateException e) {
            throw new ECKeyCreationException(
                    "Failed to load X.509 certificate from " + pemPath
                            + ": " + e.getMessage());
        }
    }

    private static Base64URL computeX509SHA256Thumbprint(X509Certificate cert) {
        try {
            byte[] derBytes = cert.getEncoded();
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(derBytes);
            return Base64URL.encode(hash);
        } catch (Exception e) {
            throw new ECKeyCreationException("Failed to compute X.509 SHA-256 thumbprint: " + e.getMessage());
        }
    }

    private static String computeJwkThumbprint(ECKey ecKey) {
        try {
            ThumbprintURI thumbprintURI = ecKey.computeThumbprintURI();
            // Extract just the hash part after "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"
            return thumbprintURI.toString().substring(thumbprintURI.toString().lastIndexOf(':') + 1);
        } catch (JOSEException e) {
            throw new ECKeyCreationException("Failed to compute JWK Thumbprint: " + e.getMessage());
        }
    }

    /**
     * Derives a did:key from a P-256 public key (legacy, used when no certificate is configured).
     * Format: did:key:z{base58btc(multicodec_prefix + compressed_pubkey)}
     * Multicodec for P-256: 0x1200 (varint: 0x80 0x24)
     */
    static String deriveDidKey(ECPublicKey publicKey) {
        byte[] compressed = compressPublicKey(publicKey);

        // Multicodec prefix for P-256 public key: 0x1200 as varint = [0x80, 0x24]
        byte[] multicodecPrefix = new byte[]{(byte) 0x80, (byte) 0x24};
        byte[] multicodecKey = new byte[multicodecPrefix.length + compressed.length];
        System.arraycopy(multicodecPrefix, 0, multicodecKey, 0, multicodecPrefix.length);
        System.arraycopy(compressed, 0, multicodecKey, multicodecPrefix.length, compressed.length);

        // Base58btc with 'z' prefix (multibase convention)
        String encoded = "z" + Base58.base58Encode(multicodecKey);

        return "did:key:" + encoded;
    }

    private static byte[] compressPublicKey(ECPublicKey publicKey) {
        byte[] x = normalizeTo32Bytes(publicKey.getW().getAffineX().toByteArray());
        byte[] y = publicKey.getW().getAffineY().toByteArray();

        byte prefix = (y[y.length - 1] & 1) == 0 ? (byte) 0x02 : (byte) 0x03;
        byte[] compressed = new byte[33];
        compressed[0] = prefix;
        System.arraycopy(x, 0, compressed, 1, 32);
        return compressed;
    }

    private static byte[] normalizeTo32Bytes(byte[] input) {
        if (input.length == 32) {
            return input;
        }
        byte[] result = new byte[32];
        if (input.length > 32) {
            // Strip leading zero(s)
            System.arraycopy(input, input.length - 32, result, 0, 32);
        } else {
            // Pad with leading zeros
            System.arraycopy(input, 0, result, 32 - input.length, input.length);
        }
        return result;
    }
}
