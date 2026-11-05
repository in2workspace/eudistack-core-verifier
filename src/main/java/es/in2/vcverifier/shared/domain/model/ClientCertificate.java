package es.in2.vcverifier.shared.domain.model;

import java.time.Instant;
import java.util.Objects;

public record ClientCertificate(
        CertificateIdentity identity,
        String issuer,
        String fingerprintSha256,
        Instant notAfter
) {

    public ClientCertificate {
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(fingerprintSha256, "fingerprintSha256");
        Objects.requireNonNull(notAfter, "notAfter");
    }
}
