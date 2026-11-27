package es.in2.vcverifier.verifier.domain.model.audit;

import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import es.in2.vcverifier.shared.domain.model.ClientCertificate;
import es.in2.vcverifier.shared.domain.model.SessionOrigin;
import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditEventType;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationAuditEntriesTest {

    private static final CertificateIdentity IDENTITY = new CertificateIdentity(
            "JOSE ANTONIO", "GARCIA FERNANDEZ", "GARCIA FERNANDEZ JOSE ANTONIO", "jose@example.com", "ES", "12345678Z");
    private static final ClientCertificate CERTIFICATE = new ClientCertificate(
            IDENTITY, "CN=AC FNMT Usuarios", "ab12cd", Instant.parse("2027-01-01T00:00:00Z"));
    private static final Map<String, Object> HOLDER = Map.of(
            "identifier", "12345678Z", "name", "JOSE ANTONIO GARCIA FERNANDEZ", "email", "jose@example.com");

    @Test
    void certificateSuccess_isTheCatalogueEventWithTheCertificateLevelAndHolder() {
        AuditEntry entry = AuthenticationAuditEntries.of(CertificateAuthenticationAudit.success("cgcom", "corr-1",
                "portal", CERTIFICATE, AssuranceLevel.HIGH, "hwk", AuditedPerson.of(IDENTITY)));

        assertThat(entry.type()).isEqualTo(AuditEventType.CERTIFICATE_AUTHENTICATION);
        assertThat(entry.type().catalogName()).isEqualTo("CertificateAuthentication");
        assertThat(entry.type().action()).isEqualTo("AuthenticateWithCertificate");
        assertThat(entry.result()).isEqualTo(AuditResult.SUCCESS);
        assertThat(entry.reason()).isNull();
        assertThat(entry.resource()).isEqualTo("login:corr-1");
        assertThat(entry.details()).containsOnly(
                Map.entry("oidc_client_id", "portal"),
                Map.entry("certificate_issuer", "CN=AC FNMT Usuarios"),
                Map.entry("certificate_fingerprint", "sha256:ab12cd"),
                Map.entry("assurance_level", "high"),
                Map.entry("amr", "hwk"),
                Map.entry("holder", HOLDER));
    }

    @Test
    void certificateSuccess_substantialLevel_isSentAsSubstantial() {
        AuditEntry entry = AuthenticationAuditEntries.of(CertificateAuthenticationAudit.success("cgcom", "corr-1",
                "portal", CERTIFICATE, AssuranceLevel.SUBSTANTIAL, "swk", AuditedPerson.of(IDENTITY)));

        assertThat(entry.details()).containsEntry("assurance_level", "substantial").containsEntry("amr", "swk");
    }

    @ParameterizedTest
    @EnumSource(value = CertificateLoginReason.class, names = {"CERTIFICATE_NOT_QUALIFIED",
            "CERTIFICATE_NOT_NATURAL_PERSON", "CERTIFICATE_EXPIRED", "CERTIFICATE_REVOKED", "LEVEL_NOT_MET"})
    void certificateRejection_isDeniedWithTheCertificateButNoHolderOrLevel(CertificateLoginReason reason) {
        AuditEntry entry = AuthenticationAuditEntries.of(CertificateAuthenticationAudit.rejected("cgcom", "corr-1",
                "portal", reason, CERTIFICATE));

        assertThat(entry.result()).isEqualTo(AuditResult.DENIED);
        assertThat(entry.reason()).isEqualTo(reason.value());
        assertThat(entry.details()).containsOnly(
                Map.entry("oidc_client_id", "portal"),
                Map.entry("certificate_issuer", "CN=AC FNMT Usuarios"),
                Map.entry("certificate_fingerprint", "sha256:ab12cd"));
    }

    @Test
    void certificateMissing_isDeniedWithOnlyTheClient() {
        AuditEntry entry = AuthenticationAuditEntries.of(CertificateAuthenticationAudit.rejected("cgcom", "corr-1",
                "portal", CertificateLoginReason.CERTIFICATE_MISSING, null));

        assertThat(entry.result()).isEqualTo(AuditResult.DENIED);
        assertThat(entry.reason()).isEqualTo("CertificateMissing");
        assertThat(entry.details()).containsOnly(Map.entry("oidc_client_id", "portal"));
    }

    @Test
    void validationUnavailable_isAFailure() {
        AuditEntry entry = AuthenticationAuditEntries.of(CertificateAuthenticationAudit.rejected("cgcom", "corr-1",
                "portal", CertificateLoginReason.VALIDATION_UNAVAILABLE, CERTIFICATE));

        assertThat(entry.result()).isEqualTo(AuditResult.FAILURE);
        assertThat(entry.reason()).isEqualTo("ValidationUnavailable");
    }

    @Test
    void sessionSuccess_isTheCatalogueEventWithOriginHolderAndClaims() {
        AuditEntry entry = AuthenticationAuditEntries.of(new IamSessionAudit("cgcom", "corr-1", "portal",
                SessionOrigin.CERTIFICATE, AuditResult.SUCCESS, AuditedPerson.of(IDENTITY),
                Map.of("given_name", "JOSE ANTONIO")));

        assertThat(entry.type()).isEqualTo(AuditEventType.IAM_SESSION_ESTABLISHED);
        assertThat(entry.type().catalogName()).isEqualTo("IamSessionEstablished");
        assertThat(entry.type().action()).isEqualTo("EstablishSession");
        assertThat(entry.result()).isEqualTo(AuditResult.SUCCESS);
        assertThat(entry.resource()).isEqualTo("login:corr-1");
        assertThat(entry.details()).containsOnly(
                Map.entry("oidc_client_id", "portal"),
                Map.entry("session_origin", "Certificate"),
                Map.entry("holder", HOLDER),
                Map.entry("identity_claims", Map.of("given_name", "JOSE ANTONIO")));
    }

    @Test
    void sessionFailure_isTokenIssuanceFailedWithoutClaims() {
        AuditEntry entry = AuthenticationAuditEntries.of(new IamSessionAudit("cgcom", "corr-1", "portal",
                SessionOrigin.SSO_REUSE, AuditResult.FAILURE, AuditedPerson.UNKNOWN, Map.of("given_name", "JOSE")));

        assertThat(entry.result()).isEqualTo(AuditResult.FAILURE);
        assertThat(entry.reason()).isEqualTo("TokenIssuanceFailed");
        assertThat(entry.details()).containsOnly(
                Map.entry("oidc_client_id", "portal"),
                Map.entry("session_origin", "SsoReuse"),
                Map.entry("holder", Map.of()));
    }

    @Test
    void sessionFromAPresentation_isSentAsPresentation() {
        AuditEntry entry = AuthenticationAuditEntries.of(new IamSessionAudit("cgcom", "corr-1", "portal",
                SessionOrigin.PRESENTATION, AuditResult.SUCCESS, AuditedPerson.UNKNOWN, null));

        assertThat(entry.details()).containsEntry("session_origin", "Presentation")
                .containsEntry("identity_claims", Map.of());
    }
}
