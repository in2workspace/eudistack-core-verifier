package es.in2.vcverifier.shared.domain.model;

public enum SessionOrigin {

    PRESENTATION("Presentation"),
    CERTIFICATE("Certificate"),
    SSO_REUSE("SsoReuse");

    private final String value;

    SessionOrigin(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static SessionOrigin of(AuthenticationResult authentication) {
        return authentication instanceof CertificateAuthentication ? CERTIFICATE : PRESENTATION;
    }
}
