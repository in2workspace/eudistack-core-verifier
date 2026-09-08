package es.in2.vcverifier.sso.infrastructure.crypto;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.port.SsoCredentialCipherPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

/**
 * AES-256-GCM implementation of {@link SsoCredentialCipherPort}. No new infrastructure
 * dependency (javax.crypto only, already on the classpath) — this is the "encrypted column"
 * alternative to Redis/ElastiCache chosen for EUD-149 production-readiness (see report §7.2).
 * <p>
 * Key handling: an unset key auto-generates an ephemeral per-process one (logged loudly) so
 * single-instance dev never needs extra setup — but only while no tenant has SSO enabled (W1
 * review, EUD-149). The moment a tenant does, a missing key fails the constructor fast instead
 * of starting with a key every replica would generate differently: a real deployment MUST set
 * {@code VERIFIER_SSO_CREDENTIAL_ENCRYPTION_KEY} to the SAME base64-encoded 32-byte value across
 * every replica sharing a tenant's database — that shared, stable key (not shared memory) is
 * what makes reuse work regardless of which replica established vs. reuses the session.
 */
@Slf4j
@Component
public class AesGcmSsoCredentialCipherAdapter implements SsoCredentialCipherPort {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final int KEY_LENGTH_BYTES = 32;

    private final SecretKey key;

    public AesGcmSsoCredentialCipherAdapter(BackendConfig backendConfig, TenantSsoConfigPort tenantSsoConfigPort) {
        String configured = backendConfig.getSsoCredentialEncryptionKey();
        if (configured == null || configured.isBlank()) {
            // W1 (review): an ephemeral per-process key silently defeats this Story's entire
            // purpose the moment there is more than one replica — this PR exists precisely so
            // establishment and reuse work across separate instances. Refuse to start rather
            // than fail opaquely later, but only when SSO is actually active somewhere: no
            // tenant has ssoEnabled=true means the key is never exercised, so an ephemeral one
            // (e.g. local/dev, or a fresh env before any tenant has been switched on) is safe.
            if (tenantSsoConfigPort.hasAnyTenantSsoEnabled()) {
                throw new IllegalStateException(
                        "VERIFIER_SSO_CREDENTIAL_ENCRYPTION_KEY is not configured, but at least one "
                                + "tenant has SSO enabled. Refusing to start with a per-process ephemeral "
                                + "key: every replica would encrypt with a different key, and SSO reuse "
                                + "would fail closed to login_required as soon as a request lands on a "
                                + "replica other than the one that established the session (EUD-149). "
                                + "Configure a shared base64-encoded AES-256 key, or disable SSO for "
                                + "every tenant if this instance is intentionally not serving it.");
            }
            log.warn("event=sso_credential_key_ephemeral reason=not_configured detail="
                    + "generating a random per-process AES-256 key: SSO reuse will fail closed "
                    + "to login_required across process restarts or any other replica until "
                    + "VERIFIER_SSO_CREDENTIAL_ENCRYPTION_KEY is set to a shared value. "
                    + "Safe for local/dev single-instance use only.");
            this.key = generateEphemeralKey();
        } else {
            this.key = decodeKey(configured);
        }
    }

    @Override
    public byte[] encrypt(String tenant, String sessionId, String plaintextJson) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            SecureRandom.getInstanceStrong().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            cipher.updateAAD(aad(tenant, sessionId));

            byte[] ciphertext = cipher.doFinal(plaintextJson.getBytes(StandardCharsets.UTF_8));

            return ByteBuffer.allocate(iv.length + ciphertext.length)
                    .put(iv)
                    .put(ciphertext)
                    .array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to encrypt SSO credential snapshot", e);
        }
    }

    @Override
    public Optional<String> decrypt(String tenant, String sessionId, byte[] stored) {
        if (stored == null || stored.length <= GCM_IV_LENGTH_BYTES) {
            return Optional.empty();
        }
        try {
            byte[] iv = Arrays.copyOfRange(stored, 0, GCM_IV_LENGTH_BYTES);
            byte[] ciphertext = Arrays.copyOfRange(stored, GCM_IV_LENGTH_BYTES, stored.length);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            cipher.updateAAD(aad(tenant, sessionId));

            byte[] plaintext = cipher.doFinal(ciphertext);
            return Optional.of(new String(plaintext, StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            // Wrong/rotated key, tampered ciphertext, or AAD (tenant/sessionId) mismatch —
            // all indistinguishable from the outside and all must fail closed, never throw.
            log.warn("event=sso_credential_decrypt_failed tenant={} reason={}", tenant, e.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    private static byte[] aad(String tenant, String sessionId) {
        return (tenant + "|" + sessionId).getBytes(StandardCharsets.UTF_8);
    }

    private static SecretKey decodeKey(String base64) {
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "VERIFIER_SSO_CREDENTIAL_ENCRYPTION_KEY is not valid base64", e);
        }
        if (raw.length != KEY_LENGTH_BYTES) {
            throw new IllegalStateException(
                    "VERIFIER_SSO_CREDENTIAL_ENCRYPTION_KEY must decode to " + KEY_LENGTH_BYTES
                            + " bytes (AES-256), got " + raw.length);
        }
        return new SecretKeySpec(raw, "AES");
    }

    private static SecretKey generateEphemeralKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(KEY_LENGTH_BYTES * 8);
            return keyGenerator.generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES not available on this JVM", e);
        }
    }
}
