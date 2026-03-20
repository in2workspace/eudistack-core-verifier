package es.in2.vcverifier.integration.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.novacrypto.base58.Base58;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Utility for building signed VPs and VCs for integration tests.
 * <p>
 * Generates ephemeral P-256 key pairs for issuer and holder,
 * produces self-signed certificates with the 2.5.4.97 OID
 * (organizationIdentifier) so that the real CertificateValidationService accepts them.
 */
public final class TestCredentialBuilder {

    // OID 2.5.4.97 = organizationIdentifier (ETSI EN 319 412-1)
    private static final ASN1ObjectIdentifier OID_ORG_IDENTIFIER = new ASN1ObjectIdentifier("2.5.4.97");

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private TestCredentialBuilder() {
    }

    // ── Key pair holder ──────────────────────────────────────────

    public record TestKeyPair(ECKey ecKey, ECPublicKey publicKey, ECPrivateKey privateKey) {
    }

    public static TestKeyPair generateKeyPair() {
        try {
            var kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            var kp = kpg.generateKeyPair();
            ECPublicKey pub = (ECPublicKey) kp.getPublic();
            ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
            ECKey ecKey = new ECKey.Builder(Curve.P_256, pub)
                    .privateKey(priv)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .build();
            return new TestKeyPair(ecKey, pub, priv);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate P-256 key pair", e);
        }
    }

    // ── Self-signed certificate with organizationIdentifier ─────

    public static X509Certificate generateCertificate(TestKeyPair keyPair, String organizationIdentifier) {
        try {
            X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            nameBuilder.addRDN(BCStyle.CN, "Test Issuer");
            nameBuilder.addRDN(BCStyle.O, "Test Organization");
            nameBuilder.addRDN(BCStyle.C, "ES");
            nameBuilder.addRDN(OID_ORG_IDENTIFIER, organizationIdentifier);

            Instant now = Instant.now();
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    nameBuilder.build(),
                    BigInteger.valueOf(now.toEpochMilli()),
                    Date.from(now.minusSeconds(3600)),
                    Date.from(now.plusSeconds(86400 * 365)),
                    nameBuilder.build(),
                    keyPair.publicKey()
            );

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(keyPair.privateKey());

            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(certBuilder.build(signer));
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate self-signed certificate", e);
        }
    }

    // ── VC (Verifiable Credential) JWT builder ──────────────────

    /**
     * Builds a signed VC JWT with the issuer key pair.
     *
     * @param issuerKeyPair    issuer's signing key
     * @param holderKeyPair    holder's key (embedded as cnf.jwk in VC claims)
     * @param issuerOrgId      issuer organizationIdentifier (for iss claim + cert)
     * @param vcPayload        the VC object (Map representing the credential body)
     * @return serialized VC JWT string
     */
    public static String buildVcJwt(TestKeyPair issuerKeyPair,
                                     TestKeyPair holderKeyPair,
                                     String issuerOrgId,
                                     Map<String, Object> vcPayload) {
        try {
            X509Certificate cert = generateCertificate(issuerKeyPair, issuerOrgId);
            List<Base64> x5c = List.of(Base64.encode(cert.getEncoded()));

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(issuerKeyPair.ecKey().getKeyID())
                    .x509CertChain(x5c)
                    .build();

            // Build cnf claim for cryptographic binding
            ECKey holderPublicJwk = new ECKey.Builder(Curve.P_256, holderKeyPair.publicKey())
                    .build();

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(issuerOrgId)
                    .claim("vc", vcPayload)
                    .claim("cnf", Map.of("jwk", holderPublicJwk.toJSONObject()))
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            JWSSigner signer = new ECDSASigner(issuerKeyPair.privateKey());
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build VC JWT", e);
        }
    }

    // ── VP (Verifiable Presentation) JWT builder ────────────────

    /**
     * Builds a signed VP JWT wrapping one or more VC JWTs.
     *
     * @param holderKeyPair holder's signing key
     * @param vcJwts        list of VC JWT strings to embed
     * @param audience      expected audience (verifier URL or client_id)
     * @param nonce         nonce for replay protection
     * @return serialized VP JWT string
     */
    public static String buildVpJwt(TestKeyPair holderKeyPair,
                                     List<String> vcJwts,
                                     String audience,
                                     String nonce) {
        try {
            // Include holder's public key in VP header for signature verification
            ECKey holderPublicJwk = new ECKey.Builder(Curve.P_256, holderKeyPair.publicKey())
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(holderKeyPair.ecKey().getKeyID())
                    .jwk(holderPublicJwk)
                    .build();

            Map<String, Object> vp = Map.of(
                    "@context", List.of("https://www.w3.org/2018/credentials/v1"),
                    "type", List.of("VerifiablePresentation"),
                    "verifiableCredential", vcJwts
            );

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .audience(audience)
                    .claim("vp", vp);

            if (nonce != null) {
                claimsBuilder.claim("nonce", nonce);
            }

            SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());
            JWSSigner signer = new ECDSASigner(holderKeyPair.privateKey());
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to build VP JWT", e);
        }
    }

    // ── M2M client_assertion JWT builder ─────────────────────────

    /**
     * Builds a client_assertion JWT for M2M (client_credentials) flow.
     * The vp_token is Base64-encoded and embedded as a claim.
     */
    public static String buildClientAssertionJwt(TestKeyPair holderKeyPair,
                                                  String vpJwt,
                                                  String audience,
                                                  String clientId) {
        try {
            String vpTokenBase64 = java.util.Base64.getEncoder()
                    .encodeToString(vpJwt.getBytes());

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(holderKeyPair.ecKey().getKeyID())
                    .build();

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(clientId)
                    .subject(clientId)
                    .audience(audience)
                    .claim("vp_token", vpTokenBase64)
                    .issueTime(new Date())
                    .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            JWSSigner signer = new ECDSASigner(holderKeyPair.privateKey());
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to build client_assertion JWT", e);
        }
    }

    // ── Credential payload factories ─────────────────────────────

    /**
     * Creates a LEARCredentialEmployee VC payload (W3C VCDM 2.0 format).
     */
    public static Map<String, Object> employeeW3cPayload(String issuerOrgId) {
        return Map.ofEntries(
                Map.entry("@context", List.of(
                        "https://www.w3.org/ns/credentials/v2",
                        "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3"
                )),
                Map.entry("id", "urn:uuid:" + UUID.randomUUID()),
                Map.entry("type", List.of("VerifiableCredential", "learcredential.employee.w3c.4")),
                Map.entry("issuer", Map.of(
                        "id", "https://issuer.example.com",
                        "organizationIdentifier", issuerOrgId,
                        "organization", "Test Organization",
                        "country", "ES",
                        "commonName", "Test Issuer"
                )),
                Map.entry("credentialSubject", Map.of(
                        "id", "did:key:zTestSubject",
                        "mandate", Map.of(
                                "mandatee", Map.of(
                                        "id", "did:key:zTestMandatee",
                                        "firstName", "John",
                                        "lastName", "Doe",
                                        "email", "john.doe@example.com"
                                ),
                                "mandator", Map.of(
                                        "organizationIdentifier", issuerOrgId,
                                        "organization", "Test Organization",
                                        "commonName", "Test Mandator",
                                        "country", "ES"
                                ),
                                "power", List.of(Map.of(
                                        "type", "domain",
                                        "domain", "https://example.com",
                                        "function", "ProductOffering",
                                        "action", List.of("Execute")
                                ))
                        )
                )),
                Map.entry("validFrom", ZonedDateTime.now().minusDays(1)
                        .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)),
                Map.entry("validUntil", ZonedDateTime.now().plusDays(365)
                        .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME))
        );
    }

    /**
     * Creates a LEARCredentialMachine VC payload (W3C VCDM 2.0 format).
     */
    public static Map<String, Object> machineW3cPayload(String issuerOrgId) {
        return Map.ofEntries(
                Map.entry("@context", List.of(
                        "https://www.w3.org/ns/credentials/v2",
                        "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_machine/w3c/v2"
                )),
                Map.entry("id", "urn:uuid:" + UUID.randomUUID()),
                Map.entry("type", List.of("VerifiableCredential", "learcredential.machine.w3c.3")),
                Map.entry("issuer", Map.of(
                        "id", "https://issuer.example.com",
                        "organizationIdentifier", issuerOrgId,
                        "organization", "Test Organization",
                        "country", "ES",
                        "commonName", "Test Issuer"
                )),
                Map.entry("credentialSubject", Map.of(
                        "id", "did:key:zTestMachineSubject",
                        "mandate", Map.of(
                                "mandatee", Map.of(
                                        "id", "did:key:zTestMachine",
                                        "domain", "api.example.com",
                                        "ipAddress", "10.0.0.1"
                                ),
                                "mandator", Map.of(
                                        "organizationIdentifier", issuerOrgId,
                                        "organization", "Test Organization",
                                        "commonName", "Test Mandator",
                                        "country", "ES"
                                ),
                                "power", List.of(Map.of(
                                        "type", "domain",
                                        "domain", "https://api.example.com",
                                        "function", "M2MAccess",
                                        "action", List.of("Execute")
                                ))
                        )
                )),
                Map.entry("validFrom", ZonedDateTime.now().minusDays(1)
                        .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)),
                Map.entry("validUntil", ZonedDateTime.now().plusDays(365)
                        .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME))
        );
    }

    // ── Convenience: full VP for H2M flow ────────────────────────

    /**
     * Creates a complete Base64-encoded VP token ready to send to /oid4vp/auth-response.
     */
    public static String buildBase64VpToken(TestKeyPair issuerKeyPair,
                                             TestKeyPair holderKeyPair,
                                             String issuerOrgId,
                                             Map<String, Object> vcPayload,
                                             String audience,
                                             String nonce) {
        String vcJwt = buildVcJwt(issuerKeyPair, holderKeyPair, issuerOrgId, vcPayload);
        String vpJwt = buildVpJwt(holderKeyPair, List.of(vcJwt), audience, nonce);
        return java.util.Base64.getEncoder().encodeToString(vpJwt.getBytes());
    }

    // ── SD-JWT VC builder ────────────────────────────────────────

    /**
     * Derives a did:key from a P-256 public key.
     * Format: did:key:z{base58btc(multicodec_prefix + compressed_pubkey)}
     * Multicodec for P-256: 0x1200 (varint: 0x80 0x24)
     */
    public static String deriveDidKey(TestKeyPair keyPair) {
        ECPublicKey pub = keyPair.publicKey();
        // Compress public key
        byte[] x = normalizeTo32Bytes(pub.getW().getAffineX().toByteArray());
        byte[] y = pub.getW().getAffineY().toByteArray();
        byte prefix = (y[y.length - 1] & 1) == 0 ? (byte) 0x02 : (byte) 0x03;
        byte[] compressed = new byte[33];
        compressed[0] = prefix;
        System.arraycopy(x, 0, compressed, 1, 32);

        // Multicodec prefix for P-256: 0x1200 as varint = [0x80, 0x24]
        byte[] multicodecPrefix = new byte[]{(byte) 0x80, (byte) 0x24};
        byte[] multicodecKey = new byte[multicodecPrefix.length + compressed.length];
        System.arraycopy(multicodecPrefix, 0, multicodecKey, 0, multicodecPrefix.length);
        System.arraycopy(compressed, 0, multicodecKey, multicodecPrefix.length, compressed.length);

        return "did:key:z" + Base58.base58Encode(multicodecKey);
    }

    private static byte[] normalizeTo32Bytes(byte[] input) {
        if (input.length == 32) return input;
        byte[] result = new byte[32];
        if (input.length > 32) {
            System.arraycopy(input, input.length - 32, result, 0, 32);
        } else {
            System.arraycopy(input, 0, result, 32 - input.length, input.length);
        }
        return result;
    }

    /**
     * Creates a Base64url-encoded disclosure: [salt, claimName, claimValue].
     */
    public static String createDisclosure(String claimName, Object claimValue) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            String json = mapper.writeValueAsString(
                    List.of(UUID.randomUUID().toString(), claimName, claimValue));
            return java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(json.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("Failed to create disclosure", e);
        }
    }

    /**
     * Computes the SHA-256 digest of a disclosure (for _sd array).
     */
    public static String computeDisclosureDigest(String disclosureEncoded) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(disclosureEncoded.getBytes(StandardCharsets.US_ASCII));
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute digest", e);
        }
    }

    /**
     * Builds a complete SD-JWT VC with disclosures and Key Binding JWT.
     * Format: issuer-jwt~disclosure1~...~disclosureN~kb-jwt
     * Uses x5c header for issuer signature (like the W3C JWT path) and
     * sets iss to the organizationIdentifier for trust framework lookup.
     *
     * @param issuerKeyPair   issuer's signing key (signs the issuer JWT)
     * @param holderKeyPair   holder's key (cnf binding + KB-JWT signer)
     * @param issuerOrgId     issuer organizationIdentifier (for iss claim + cert)
     * @param vct             verifiable credential type (e.g., "learcredential.employee.sd.1")
     * @param disclosedClaims claims to disclose (each becomes a disclosure)
     * @param directClaims    claims embedded directly in the issuer JWT (not disclosed)
     * @param audience        expected audience for KB-JWT
     * @param nonce           nonce for KB-JWT replay protection
     * @return compact SD-JWT string
     */
    public static String buildSdJwt(TestKeyPair issuerKeyPair,
                                     TestKeyPair holderKeyPair,
                                     String issuerOrgId,
                                     String vct,
                                     Map<String, Object> disclosedClaims,
                                     Map<String, Object> directClaims,
                                     String audience,
                                     String nonce) {
        try {
            // 1. Create disclosures and compute digests
            List<String> disclosureEncodings = new java.util.ArrayList<>();
            List<String> digests = new java.util.ArrayList<>();
            for (var entry : disclosedClaims.entrySet()) {
                String enc = createDisclosure(entry.getKey(), entry.getValue());
                disclosureEncodings.add(enc);
                digests.add(computeDisclosureDigest(enc));
            }

            // 2. Build holder cnf
            ECKey holderPublicJwk = new ECKey.Builder(Curve.P_256, holderKeyPair.publicKey()).build();

            // 3. Build issuer JWT with x5c (same approach as W3C JWT path)
            X509Certificate cert = generateCertificate(issuerKeyPair, issuerOrgId);
            List<Base64> x5c = List.of(Base64.encode(cert.getEncoded()));

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(issuerOrgId)
                    .claim("vct", vct)
                    .claim("_sd", digests)
                    .claim("_sd_alg", "SHA-256")
                    .claim("cnf", Map.of("jwk", holderPublicJwk.toJSONObject()))
                    .issueTime(new Date())
                    .expirationTime(Date.from(Instant.now().plusSeconds(86400)));

            // Add direct (non-disclosed) claims
            for (var entry : directClaims.entrySet()) {
                claimsBuilder.claim(entry.getKey(), entry.getValue());
            }

            JWSHeader issuerHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(issuerKeyPair.ecKey().getKeyID())
                    .x509CertChain(x5c)
                    .build();

            SignedJWT issuerJwt = new SignedJWT(issuerHeader, claimsBuilder.build());
            issuerJwt.sign(new ECDSASigner(issuerKeyPair.privateKey()));
            String issuerJwtStr = issuerJwt.serialize();

            // 4. Build the prefix for sd_hash: issuerJwt~disc1~disc2~...~
            StringBuilder sdHashInput = new StringBuilder(issuerJwtStr);
            for (String disc : disclosureEncodings) {
                sdHashInput.append('~').append(disc);
            }
            sdHashInput.append('~');

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(sdHashInput.toString().getBytes(StandardCharsets.US_ASCII));
            String sdHash = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

            // 5. Build KB-JWT
            JWSHeader kbHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new com.nimbusds.jose.JOSEObjectType("kb+jwt"))
                    .build();

            JWTClaimsSet kbClaims = new JWTClaimsSet.Builder()
                    .audience(audience)
                    .claim("nonce", nonce)
                    .claim("sd_hash", sdHash)
                    .issueTime(new Date())
                    .build();

            SignedJWT kbJwt = new SignedJWT(kbHeader, kbClaims);
            kbJwt.sign(new ECDSASigner(holderKeyPair.privateKey()));
            String kbJwtStr = kbJwt.serialize();

            // 6. Assemble: issuer-jwt~disc1~disc2~...~kb-jwt
            StringBuilder compact = new StringBuilder(issuerJwtStr);
            for (String disc : disclosureEncodings) {
                compact.append('~').append(disc);
            }
            compact.append('~').append(kbJwtStr);

            return compact.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build SD-JWT", e);
        }
    }

    // ── SD-JWT payload factories ─────────────────────────────────

    /**
     * Disclosed claims for LEARCredentialEmployee SD-JWT.
     * These become disclosures (not directly in the issuer JWT).
     */
    public static Map<String, Object> employeeSdJwtDisclosedClaims(String issuerOrgId) {
        return Map.of(
                "mandatee", Map.of(
                        "id", "did:key:zTestMandatee",
                        "firstName", "John",
                        "lastName", "Doe",
                        "email", "john.doe@example.com"
                ),
                "mandator", Map.of(
                        "organizationIdentifier", issuerOrgId,
                        "organization", "Test Organization",
                        "commonName", "Test Mandator",
                        "country", "ES"
                ),
                "power", List.of(Map.of(
                        "type", "domain",
                        "domain", "https://example.com",
                        "function", "ProductOffering",
                        "action", List.of("Execute")
                ))
        );
    }

    /**
     * Disclosed claims for LEARCredentialMachine SD-JWT.
     */
    public static Map<String, Object> machineSdJwtDisclosedClaims(String issuerOrgId) {
        return Map.of(
                "mandatee", Map.of(
                        "id", "did:key:zTestMachine",
                        "domain", "api.example.com",
                        "ipAddress", "10.0.0.1"
                ),
                "mandator", Map.of(
                        "organizationIdentifier", issuerOrgId,
                        "organization", "Test Organization",
                        "commonName", "Test Mandator",
                        "country", "ES"
                ),
                "power", List.of(Map.of(
                        "type", "domain",
                        "domain", "https://api.example.com",
                        "function", "M2MAccess",
                        "action", List.of("Execute")
                ))
        );
    }

    /**
     * Builds a Base64-encoded SD-JWT VP token for H2M flow.
     */
    public static String buildBase64SdJwtVpToken(TestKeyPair issuerKeyPair,
                                                  TestKeyPair holderKeyPair,
                                                  String issuerOrgId,
                                                  String vct,
                                                  Map<String, Object> disclosedClaims,
                                                  Map<String, Object> directClaims,
                                                  String audience,
                                                  String nonce) {
        String sdJwt = buildSdJwt(issuerKeyPair, holderKeyPair, issuerOrgId, vct,
                disclosedClaims, directClaims, audience, nonce);
        return java.util.Base64.getEncoder().encodeToString(sdJwt.getBytes());
    }
}
