package es.in2.vcverifier.shared.crypto;

import es.in2.vcverifier.shared.config.properties.CertificateLoginProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

@Service
public class CertificateSubjectService {

    public static final String SUBJECT_KEY_PROPERTY = "verifier.certificate-login.subject-key";
    public static final String SUBJECT_KEY_VARIABLE = "VERIFIER_CERTIFICATELOGIN_SUBJECTKEY";
    static final int MIN_KEY_BYTES = 32;
    private static final String ALGORITHM = "HmacSHA256";
    private static final String SEPARATOR = "|";

    private final byte[] key;

    public CertificateSubjectService(@Value("${" + SUBJECT_KEY_PROPERTY + ":}") String key,
                                     CertificateLoginProperties certificateLoginProperties) {
        this.key = key == null ? new byte[0] : key.getBytes(StandardCharsets.UTF_8);
        if (!certificateLoginProperties.tenants().isEmpty() && this.key.length < MIN_KEY_BYTES) {
            throw new IllegalStateException("Certificate login is active for tenants "
                    + certificateLoginProperties.tenants().keySet() + " but " + SUBJECT_KEY_VARIABLE + " ("
                    + SUBJECT_KEY_PROPERTY + ") is " + (this.key.length == 0 ? "not configured" : "shorter than "
                    + MIN_KEY_BYTES + " bytes"));
        }
    }

    public String subject(String tenant, String country, String number) {
        if (key.length == 0) {
            throw new IllegalStateException(SUBJECT_KEY_VARIABLE + " is not configured");
        }
        if (isBlank(tenant) || isBlank(country) || isBlank(number)) {
            throw new IllegalArgumentException("Tenant, country and number are required for the certificate subject");
        }
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(key, ALGORITHM));
            byte[] digest = mac.doFinal(String.join(SEPARATOR, tenant, country, number).getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot compute the certificate subject", e);
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
