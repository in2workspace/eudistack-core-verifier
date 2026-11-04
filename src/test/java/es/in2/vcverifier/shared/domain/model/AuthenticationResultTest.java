package es.in2.vcverifier.shared.domain.model;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthenticationResultTest {

    private static final Instant AUTH_TIME = Instant.ofEpochSecond(1_700_000_000L);
    private static final CertificateIdentity IDENTITY = new CertificateIdentity(
            "JOSE ANTONIO", "GARCIA FERNANDEZ", "GARCIA FERNANDEZ JOSE ANTONIO",
            "jgarcia@example.com", "ES", "12345678Z");

    @Test
    void credentialAuthentication_isTheWalletMethodWithProofOfPossession() {
        CredentialAuthentication authentication = new CredentialAuthentication(
                JsonNodeFactory.instance.objectNode(), AssuranceLevel.SUBSTANTIAL, AUTH_TIME);

        assertThat(authentication.method()).isEqualTo(LoginMethod.WALLET);
        assertThat(authentication.amr()).containsExactly("pop");
        assertThat(authentication.acr()).isEqualTo(AssuranceLevel.SUBSTANTIAL);
        assertThat(authentication.authTime()).isEqualTo(AUTH_TIME);
    }

    @Test
    void credentialAuthentication_withoutDeclaredLevel_hasNoAcr() {
        assertThat(new CredentialAuthentication(JsonNodeFactory.instance.objectNode(), null, AUTH_TIME).acr()).isNull();
    }

    @Test
    void credentialAuthentication_requiresTheCredentialAndTheAuthTime() {
        assertThatThrownBy(() -> new CredentialAuthentication(null, null, AUTH_TIME))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new CredentialAuthentication(JsonNodeFactory.instance.objectNode(), null, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void certificateAuthentication_isTheX509MethodWithItsOwnAmr() {
        List<String> amr = new ArrayList<>(List.of("hwk"));
        CertificateAuthentication authentication = new CertificateAuthentication(
                IDENTITY, "CN=AC FNMT Usuarios", "ab12", AUTH_TIME.plusSeconds(3600), AssuranceLevel.HIGH, amr, AUTH_TIME);
        amr.add("swk");

        assertThat(authentication.method()).isEqualTo(LoginMethod.X509);
        assertThat(authentication.amr()).containsExactly("hwk");
        assertThat(authentication.acr()).isEqualTo(AssuranceLevel.HIGH);
    }

    @Test
    void certificateAuthentication_requiresTheIdentityTheLevelAndTheAuthTime() {
        assertThatThrownBy(() -> new CertificateAuthentication(
                null, "issuer", "ab12", AUTH_TIME, AssuranceLevel.HIGH, List.of("hwk"), AUTH_TIME))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new CertificateAuthentication(
                IDENTITY, "issuer", "ab12", AUTH_TIME, null, List.of("hwk"), AUTH_TIME))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new CertificateAuthentication(
                IDENTITY, "issuer", "ab12", AUTH_TIME, AssuranceLevel.HIGH, List.of("hwk"), null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void certificateIdentity_neverPrintsThePersonalData() {
        CertificateAuthentication authentication = new CertificateAuthentication(
                IDENTITY, "issuer", "ab12", AUTH_TIME, AssuranceLevel.HIGH, List.of("hwk"), AUTH_TIME);

        assertThat(authentication.toString())
                .doesNotContain("12345678Z", "GARCIA", "jgarcia@example.com")
                .contains("CertificateIdentity[redacted]");
    }
}
