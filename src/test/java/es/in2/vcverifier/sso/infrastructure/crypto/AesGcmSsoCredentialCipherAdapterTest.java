package es.in2.vcverifier.sso.infrastructure.crypto;

import es.in2.vcverifier.shared.config.BackendConfig;
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
        AesGcmSsoCredentialCipherAdapter cipher = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomKey()));

        byte[] ciphertext = cipher.encrypt(TENANT, SESSION_ID, "{\"sub\":\"holder-1\"}");
        Optional<String> plaintext = cipher.decrypt(TENANT, SESSION_ID, ciphertext);

        assertThat(plaintext).contains("{\"sub\":\"holder-1\"}");
    }

    @Test
    void encrypt_isNonDeterministic_randomIvPerCall() {
        AesGcmSsoCredentialCipherAdapter cipher = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomKey()));

        byte[] first = cipher.encrypt(TENANT, SESSION_ID, "same-plaintext");
        byte[] second = cipher.encrypt(TENANT, SESSION_ID, "same-plaintext");

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void decrypt_withDifferentKey_returnsEmpty_neverThrows() {
        AesGcmSsoCredentialCipherAdapter encryptor = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomKey()));
        AesGcmSsoCredentialCipherAdapter decryptor = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomKey()));

        byte[] ciphertext = encryptor.encrypt(TENANT, SESSION_ID, "{\"sub\":\"holder-1\"}");

        assertThat(decryptor.decrypt(TENANT, SESSION_ID, ciphertext)).isEmpty();
    }

    @Test
    void decrypt_withWrongTenantAad_returnsEmpty_evenWithCorrectKey() {
        String key = randomKey();
        AesGcmSsoCredentialCipherAdapter cipher = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(key));

        byte[] ciphertext = cipher.encrypt("tenant-a", SESSION_ID, "{\"sub\":\"holder-1\"}");

        assertThat(cipher.decrypt("tenant-b", SESSION_ID, ciphertext)).isEmpty();
    }

    @Test
    void decrypt_withWrongSessionIdAad_returnsEmpty_evenWithCorrectKey() {
        String key = randomKey();
        AesGcmSsoCredentialCipherAdapter cipher = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(key));

        byte[] ciphertext = cipher.encrypt(TENANT, "session-original", "{\"sub\":\"holder-1\"}");

        assertThat(cipher.decrypt(TENANT, "session-other", ciphertext)).isEmpty();
    }

    @Test
    void decrypt_withTamperedCiphertext_returnsEmpty() {
        AesGcmSsoCredentialCipherAdapter cipher = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomKey()));

        byte[] ciphertext = cipher.encrypt(TENANT, SESSION_ID, "{\"sub\":\"holder-1\"}");
        ciphertext[ciphertext.length - 1] ^= 0x01; // flip the last byte of the GCM tag

        assertThat(cipher.decrypt(TENANT, SESSION_ID, ciphertext)).isEmpty();
    }

    @Test
    void decrypt_withNullOrTooShortCiphertext_returnsEmpty() {
        AesGcmSsoCredentialCipherAdapter cipher = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomKey()));

        assertThat(cipher.decrypt(TENANT, SESSION_ID, null)).isEmpty();
        assertThat(cipher.decrypt(TENANT, SESSION_ID, new byte[]{1, 2, 3})).isEmpty();
    }

    @Test
    void constructor_withBlankKey_generatesEphemeralKey_stillRoundTrips() {
        AesGcmSsoCredentialCipherAdapter cipher = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(""));

        byte[] ciphertext = cipher.encrypt(TENANT, SESSION_ID, "{\"sub\":\"holder-1\"}");

        assertThat(cipher.decrypt(TENANT, SESSION_ID, ciphertext)).contains("{\"sub\":\"holder-1\"}");
    }

    @Test
    void constructor_withNullKey_generatesEphemeralKey_stillRoundTrips() {
        AesGcmSsoCredentialCipherAdapter cipher = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(null));

        byte[] ciphertext = cipher.encrypt(TENANT, SESSION_ID, "{\"sub\":\"holder-1\"}");

        assertThat(cipher.decrypt(TENANT, SESSION_ID, ciphertext)).contains("{\"sub\":\"holder-1\"}");
    }

    @Test
    void constructor_withWrongLengthKey_throwsImmediately() {
        String tooShort = Base64.getEncoder().encodeToString(new byte[16]);

        assertThatThrownBy(() -> new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(tooShort)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    void constructor_withInvalidBase64Key_throwsImmediately() {
        assertThatThrownBy(() -> new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey("not-valid-base64!!")))
                .isInstanceOf(IllegalStateException.class);
    }

    private static BackendConfig backendConfigWithKey(String base64Key) {
        BackendConfig backendConfig = mock(BackendConfig.class);
        when(backendConfig.getSsoCredentialEncryptionKey()).thenReturn(base64Key);
        return backendConfig;
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
