package es.in2.vcverifier.shared.domain.model;

public record CertificateIdentity(
        String givenName,
        String surname,
        String commonName,
        String email,
        String country,
        String personalAdministrativeNumber
) {

    @Override
    public String toString() {
        return "CertificateIdentity[redacted]";
    }
}
