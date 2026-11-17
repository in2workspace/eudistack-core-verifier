package es.in2.vcverifier.shared.domain.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

public record CertificateAuthentication(
        String subject,
        CertificateIdentity identity,
        String issuer,
        String fingerprintSha256,
        Instant notAfter,
        AssuranceLevel acr,
        List<String> amr,
        Instant authTime
) implements AuthenticationResult {

    public CertificateAuthentication {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(acr, "acr");
        Objects.requireNonNull(authTime, "authTime");
        amr = List.copyOf(amr);
    }

    @Override
    public LoginMethod method() {
        return LoginMethod.X509;
    }
}
