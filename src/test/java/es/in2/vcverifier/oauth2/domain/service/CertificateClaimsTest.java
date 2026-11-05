package es.in2.vcverifier.oauth2.domain.service;

import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

class CertificateClaimsTest {

    private static final CertificateIdentity IDENTITY = new CertificateIdentity(
            "JOSE ANTONIO", "GARCIA FERNANDEZ", "GARCIA FERNANDEZ JOSE ANTONIO",
            "jgarcia@example.com", "ES", "12345678Z");

    @Test
    void forScopes_profile_givesTheNames() {
        assertThat(CertificateClaims.forScopes(IDENTITY, Set.of("openid", "profile")))
                .containsOnly(
                        entry("given_name", "JOSE ANTONIO"),
                        entry("family_name", "GARCIA FERNANDEZ"),
                        entry("name", "GARCIA FERNANDEZ JOSE ANTONIO"));
    }

    @Test
    void forScopes_emailAndNumber_giveOnlyThoseClaims() {
        assertThat(CertificateClaims.forScopes(IDENTITY, List.of("email", "personal_administrative_number")))
                .containsOnly(
                        entry("email", "jgarcia@example.com"),
                        entry("personal_administrative_number", "12345678Z"));
    }

    @Test
    void forScopes_withoutIdentityScopes_givesNoClaims() {
        assertThat(CertificateClaims.forScopes(IDENTITY, Set.of("openid"))).isEmpty();
    }

    @Test
    void forScopes_leavesOutTheFieldsTheCertificateDoesNotHave() {
        CertificateIdentity withoutEmail = new CertificateIdentity(
                "JOSE ANTONIO", "GARCIA FERNANDEZ", "GARCIA FERNANDEZ JOSE ANTONIO", null, "ES", "12345678Z");

        assertThat(CertificateClaims.forScopes(withoutEmail, Set.of("profile", "email")))
                .doesNotContainKey("email")
                .containsKey("given_name");
    }
}
