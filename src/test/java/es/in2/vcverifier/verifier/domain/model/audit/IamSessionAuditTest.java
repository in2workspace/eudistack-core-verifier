package es.in2.vcverifier.verifier.domain.model.audit;

import es.in2.vcverifier.shared.domain.model.SessionOrigin;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IamSessionAuditTest {

    private static final AuditedPerson HOLDER = new AuditedPerson("12345678Z", "JOSE ANTONIO GARCIA FERNANDEZ", null);

    @Test
    void success_keepsTheIdentityClaimsAndHasNoReason() {
        IamSessionAudit audit = new IamSessionAudit("cgcom", "corr-1", "portal", SessionOrigin.CERTIFICATE,
                AuditResult.SUCCESS, HOLDER, Map.of("given_name", "JOSE ANTONIO"));

        assertThat(audit.reason()).isNull();
        assertThat(audit.identityClaims()).containsExactly(Map.entry("given_name", "JOSE ANTONIO"));
    }

    @Test
    void success_withoutClaims_hasAnEmptyMap() {
        IamSessionAudit audit = new IamSessionAudit("cgcom", "corr-1", "portal", SessionOrigin.PRESENTATION,
                AuditResult.SUCCESS, HOLDER, null);

        assertThat(audit.identityClaims()).isEmpty();
    }

    @Test
    void failure_isTokenIssuanceFailedAndDropsTheClaims() {
        IamSessionAudit audit = new IamSessionAudit("cgcom", "corr-1", "portal", SessionOrigin.SSO_REUSE,
                AuditResult.FAILURE, HOLDER, Map.of("given_name", "JOSE ANTONIO"));

        assertThat(audit.reason()).isEqualTo(IamSessionAudit.TOKEN_ISSUANCE_FAILED);
        assertThat(audit.identityClaims()).isNull();
    }

    @Test
    void denied_isNotAResultOfTheEvent() {
        assertThatThrownBy(() -> new IamSessionAudit("cgcom", "corr-1", "portal", SessionOrigin.CERTIFICATE,
                AuditResult.DENIED, HOLDER, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void toString_neverShowsTheHolderOrTheClaims() {
        IamSessionAudit audit = new IamSessionAudit("cgcom", "corr-1", "portal", SessionOrigin.CERTIFICATE,
                AuditResult.SUCCESS, HOLDER, Map.of("personal_administrative_number", "12345678Z"));

        assertThat(audit.toString()).doesNotContain("12345678Z", "JOSE");
    }
}
