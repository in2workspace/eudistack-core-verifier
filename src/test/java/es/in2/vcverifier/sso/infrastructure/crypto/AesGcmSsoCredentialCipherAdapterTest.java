package es.in2.vcverifier.sso.infrastructure.crypto;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AesGcmSsoCredentialCipherAdapterTest {

    private static final String TENANT = "tenant-a";
    private static final String SESSION_ID = "session-123";

    @Test
    void encryptThenDecrypt_withSameKeyAndAad_returnsOriginalPlaintext() {
        AesGcmSsoCredentialCipherAdapter cipher =
                new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomKey()), noTenantSsoEnabled());

        byte[] ciphertext = cipher.encrypt(TENANT, SESSION_ID, "{\"sub\":\"holder-1\"}");
        Optional<String> plaintext = cipher.decrypt(TENANT, SESSION_ID, ciphertext);

        assertThat(plaintext).contains("{\"sub\":\"holder-1\"}");
    }

    @Test
    void encrypt_isNonDeterministic_randomIvPerCall() {
        AesGcmSsoCredentialCipherAdapter cipher =
                new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomKey()), noTenantSsoEnabled());

        byte[] first = cipher.encrypt(TENANT, SESSION_ID, "same-plaintext");
        byte[] second = cipher.encrypt(TENANT, SESSION_ID, "same-plaintext");

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void decrypt_withDifferentKey_returnsEmpty_neverThrows() {
        AesGcmSsoCredentialCipherAdapter encryptor =
                new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomKey()), noTenantSsoEnabled());
        AesGcmSsoCredentialCipherAdapter decryptor =
                new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomKey()), noTenantSsoEnabled());

        byte[] ciphertext = encryptor.encrypt(TENANT, SESSION_ID, "{\"sub\":\"holder-1\"}");

        assertThat(decryptor.decrypt(TENANT, SESSION_ID, ciphertext)).isEmpty();
    }

    @Test
    void decrypt_withWrongTenantAad_returnsEmpty_evenWithCorrectKey() {
        String key = randomKey();
        AesGcmSsoCredentialCipherAdapter cipher =
                new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(key), noTenantSsoEnabled());

        byte[] ciphertext = cipher.encrypt("tenant-a", SESSION_ID, "{\"sub\":\"holder-1\"}");

        assertThat(cipher.decrypt("tenant-b", SESSION_ID, ciphertext)).isEmpty();
    }

    @Test
    void decrypt_withWrongSessionIdAad_returnsEmpty_evenWithCorrectKey() {
        String key = randomKey();
        AesGcmSsoCredentialCipherAdapter cipher =
                new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(key), noTenantSsoEnabled());

        byte[] ciphertext = cipher.encrypt(TENANT, "session-original", "{\"sub\":\"holder-1\"}");

        assertThat(cipher.decrypt(TENANT, "session-other", ciphertext)).isEmpty();
    }

    @Test
    void decrypt_withTamperedCiphertext_returnsEmpty() {
        AesGcmSsoCredentialCipherAdapter cipher =
                new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomKey()), noTenantSsoEnabled());

        byte[] ciphertext = cipher.encrypt(TENANT, SESSION_ID, "{\"sub\":\"holder-1\"}");
        ciphertext[ciphertext.length - 1] ^= 0x01; // flip the last byte of the GCM tag

        assertThat(cipher.decrypt(TENANT, SESSION_ID, ciphertext)).isEmpty();
    }

    @Test
    void decrypt_withNullOrTooShortCiphertext_returnsEmpty() {
        AesGcmSsoCredentialCipherAdapter cipher =
                new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomKey()), noTenantSsoEnabled());

        assertThat(cipher.decrypt(TENANT, SESSION_ID, null)).isEmpty();
        assertThat(cipher.decrypt(TENANT, SESSION_ID, new byte[]{1, 2, 3})).isEmpty();
    }

    @Test
    void constructor_withBlankKeyAndNoTenantSsoEnabled_generatesEphemeralKey_stillRoundTrips() {
        AesGcmSsoCredentialCipherAdapter cipher =
                new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(""), noTenantSsoEnabled());

        byte[] ciphertext = cipher.encrypt(TENANT, SESSION_ID, "{\"sub\":\"holder-1\"}");

        assertThat(cipher.decrypt(TENANT, SESSION_ID, ciphertext)).contains("{\"sub\":\"holder-1\"}");
    }

    @Test
    void constructor_withNullKeyAndNoTenantSsoEnabled_generatesEphemeralKey_stillRoundTrips() {
        AesGcmSsoCredentialCipherAdapter cipher =
                new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(null), noTenantSsoEnabled());

        byte[] ciphertext = cipher.encrypt(TENANT, SESSION_ID, "{\"sub\":\"holder-1\"}");

        assertThat(cipher.decrypt(TENANT, SESSION_ID, ciphertext)).contains("{\"sub\":\"holder-1\"}");
    }

    @Test
    void constructor_withBlankKeyAndSomeTenantSsoEnabled_throwsImmediately_failFast() {
        // W1 (review): a missing key must never be silently papered over with an ephemeral,
        // per-process one while SSO is actually active for some tenant — that would defeat this
        // whole Story (reuse across replicas) opaquely.
        TenantSsoConfigPort tenantSsoConfigPort = mock(TenantSsoConfigPort.class);
        when(tenantSsoConfigPort.hasAnyTenantSsoEnabled()).thenReturn(true);

        assertThatThrownBy(() -> new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(""), tenantSsoConfigPort))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("VERIFIER_SSO_CREDENTIAL_ENCRYPTION_KEY");
    }

    @Test
    void constructor_withWrongLengthKey_throwsImmediately() {
        String tooShort = Base64.getEncoder().encodeToString(new byte[16]);

        assertThatThrownBy(() ->
                new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(tooShort), noTenantSsoEnabled()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    void constructor_withInvalidBase64Key_throwsImmediately() {
        assertThatThrownBy(() ->
                new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey("not-valid-base64!!"), noTenantSsoEnabled()))
                .isInstanceOf(IllegalStateException.class);
    }

    private static BackendConfig backendConfigWithKey(String base64Key) {
        BackendConfig backendConfig = mock(BackendConfig.class);
        when(backendConfig.getSsoCredentialEncryptionKey()).thenReturn(base64Key);
        return backendConfig;
    }

    /** Default Mockito stub (unstubbed boolean -> false) already means "no tenant enabled". */
    private static TenantSsoConfigPort noTenantSsoEnabled() {
        return mock(TenantSsoConfigPort.class);
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
