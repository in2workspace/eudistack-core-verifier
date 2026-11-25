package es.in2.vcverifier.verifier.domain.model.audit;

import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import es.in2.vcverifier.shared.domain.model.ClientCertificate;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateAuthenticationAuditTest {

    @Test
    void toString_neverShowsTheHolderOrTheCertificate() {
        ClientCertificate certificate = new ClientCertificate(new CertificateIdentity("JOSE ANTONIO", "GARCIA FERNANDEZ",
                "GARCIA FERNANDEZ JOSE ANTONIO", "jose@example.com", "ES", "12345678Z"), "CN=AC FNMT Usuarios",
                "ab12cd", Instant.parse("2027-01-01T00:00:00Z"));
        CertificateAuthenticationAudit audit = CertificateAuthenticationAudit.success("cgcom", "corr-1", "portal",
                certificate, AssuranceLevel.HIGH, "hwk", AuditedPerson.of(certificate.identity()));

        assertThat(audit.toString())
                .isEqualTo("CertificateAuthenticationAudit[clientId=portal, result=SUCCESS, reason=null]")
                .doesNotContain("12345678Z", "JOSE", "jose@example.com", "ab12cd", "AC FNMT");
    }

    private static final ClientCertificate CERTIFICATE = new ClientCertificate(
            new CertificateIdentity("JOSE ANTONIO", "GARCIA FERNANDEZ", "NAME", null, "ES", "12345678Z"),
            "CN=AC FNMT Usuarios", "sha256:ab12", Instant.parse("2027-01-01T00:00:00Z"));

    @Test
    void success_isASuccessWithTheCertificateLevelAndHolder() {
        AuditedPerson holder = new AuditedPerson("12345678Z", "JOSE ANTONIO GARCIA FERNANDEZ", null);

        CertificateAuthenticationAudit audit = CertificateAuthenticationAudit.success("cgcom", "corr-1", "portal",
                CERTIFICATE, AssuranceLevel.SUBSTANTIAL, "swk", holder);

        assertThat(audit.result()).isEqualTo(AuditResult.SUCCESS);
        assertThat(audit.reason()).isNull();
        assertThat(audit.certificateIssuer()).isEqualTo("CN=AC FNMT Usuarios");
        assertThat(audit.certificateFingerprint()).isEqualTo("sha256:ab12");
        assertThat(audit.assuranceLevel()).isEqualTo(AssuranceLevel.SUBSTANTIAL);
        assertThat(audit.amr()).isEqualTo("swk");
        assertThat(audit.holder()).isEqualTo(holder);
    }

    @ParameterizedTest
    @EnumSource(value = CertificateLoginReason.class, names = {"CERTIFICATE_MISSING", "CERTIFICATE_NOT_QUALIFIED",
            "CERTIFICATE_NOT_NATURAL_PERSON", "CERTIFICATE_EXPIRED", "CERTIFICATE_REVOKED", "LEVEL_NOT_MET"})
    void rejected_catalogueDeniedReasons_areDenied(CertificateLoginReason reason) {
        CertificateAuthenticationAudit audit = CertificateAuthenticationAudit.rejected("cgcom", "corr-1", "portal",
                reason, CERTIFICATE);

        assertThat(audit.result()).isEqualTo(AuditResult.DENIED);
        assertThat(audit.holder()).isNull();
        assertThat(audit.assuranceLevel()).isNull();
        assertThat(audit.amr()).isNull();
    }

    @Test
    void rejected_validationUnavailable_isAFailure() {
        CertificateAuthenticationAudit audit = CertificateAuthenticationAudit.rejected("cgcom", "corr-1", "portal",
                CertificateLoginReason.VALIDATION_UNAVAILABLE, CERTIFICATE);

        assertThat(audit.result()).isEqualTo(AuditResult.FAILURE);
    }

    @Test
    void rejected_withoutCertificate_omitsTheCertificateData() {
        CertificateAuthenticationAudit audit = CertificateAuthenticationAudit.rejected("cgcom", "corr-1", "portal",
                CertificateLoginReason.CERTIFICATE_MISSING, null);

        assertThat(audit.certificateIssuer()).isNull();
        assertThat(audit.certificateFingerprint()).isNull();
    }

    @ParameterizedTest
    @EnumSource(value = CertificateLoginReason.class, names = {"LOGIN_NOT_FOUND", "INTERNAL_ERROR"})
    void rejected_reasonsOutsideTheCatalogue_areRefused(CertificateLoginReason reason) {
        assertThatThrownBy(() -> CertificateAuthenticationAudit.rejected("cgcom", "corr-1", "portal", reason, CERTIFICATE))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void anEventWithoutCorrelationId_isRefused() {
        assertThatThrownBy(() -> CertificateAuthenticationAudit.rejected("cgcom", null, "portal",
                CertificateLoginReason.CERTIFICATE_MISSING, null))
                .isInstanceOf(NullPointerException.class);
    }
}
