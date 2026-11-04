package es.in2.vcverifier.verifier.domain.model;

public enum CertificateLoginReason {

    CERTIFICATE_NOT_NATURAL_PERSON("CertificateNotNaturalPerson"),
    CERTIFICATE_NOT_QUALIFIED("CertificateNotQualified"),
    CERTIFICATE_REVOKED("CertificateRevoked"),
    CERTIFICATE_EXPIRED("CertificateExpired"),
    VALIDATION_UNAVAILABLE("ValidationUnavailable");

    private final String value;

    CertificateLoginReason(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
