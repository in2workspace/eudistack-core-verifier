package es.in2.vcverifier.sso.application.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.AuthenticationResult;
import es.in2.vcverifier.shared.domain.model.CertificateAuthentication;
import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import es.in2.vcverifier.shared.domain.model.CredentialAuthentication;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationSnapshotTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Instant AUTH_TIME = Instant.ofEpochSecond(1_700_000_000L);
    private static final Instant ESTABLISHED_AT = Instant.ofEpochSecond(1_700_000_500L);

    @Test
    void credentialAuthentication_roundTripsWithItsLevelAndAuthTime() throws Exception {
        CredentialAuthentication credential = new CredentialAuthentication(
                MAPPER.readTree("{\"vct\":\"learcredential.employee.sd.1\",\"sub\":\"holder-1\"}"),
                AssuranceLevel.SUBSTANTIAL, AUTH_TIME);

        Optional<AuthenticationResult> read = AuthenticationSnapshot.read(AuthenticationSnapshot.write(credential), ESTABLISHED_AT);

        assertThat(read).contains(credential);
    }

    @Test
    void certificateAuthentication_roundTripsWithItsIdentityAndCertificate() {
        CertificateAuthentication certificate = new CertificateAuthentication("b2f1c3",
                new CertificateIdentity("JOSE ANTONIO", "GARCIA FERNANDEZ", "GARCIA FERNANDEZ JOSE ANTONIO",
                        null, "ES", "12345678Z"),
                "CN=AC FNMT Usuarios", "ab12", Instant.ofEpochSecond(1_800_000_000L),
                AssuranceLevel.HIGH, List.of("hwk"), AUTH_TIME);

        Optional<AuthenticationResult> read = AuthenticationSnapshot.read(AuthenticationSnapshot.write(certificate), ESTABLISHED_AT);

        assertThat(read).contains(certificate);
    }

    @Test
    void snapshotWithoutType_isReadAsACredentialAuthenticatedWhenTheSessionWasEstablished() throws Exception {
        String legacy = "{\"type\":[\"VerifiableCredential\",\"learcredential.employee.w3c.4\"],\"sub\":\"holder-1\"}";

        Optional<AuthenticationResult> read = AuthenticationSnapshot.read(legacy, ESTABLISHED_AT);

        assertThat(read).contains(new CredentialAuthentication(MAPPER.readTree(legacy), null, ESTABLISHED_AT));
    }

    @Test
    void snapshotWithoutAuthTime_usesTheEstablishment() {
        Optional<AuthenticationResult> read = AuthenticationSnapshot.read(
                "{\"snapshot_type\":\"credential\",\"credential\":{\"sub\":\"holder-1\"}}", ESTABLISHED_AT);

        assertThat(read).hasValueSatisfying(authentication ->
                assertThat(authentication.authTime()).isEqualTo(ESTABLISHED_AT));
    }

    @Test
    void unreadableOrUnknownSnapshot_isEmpty() {
        assertThat(AuthenticationSnapshot.read("not json", ESTABLISHED_AT)).isEmpty();
        assertThat(AuthenticationSnapshot.read("[1,2]", ESTABLISHED_AT)).isEmpty();
        assertThat(AuthenticationSnapshot.read("{\"snapshot_type\":\"password\"}", ESTABLISHED_AT)).isEmpty();
        assertThat(AuthenticationSnapshot.read("{\"snapshot_type\":\"certificate\"}", ESTABLISHED_AT)).isEmpty();
    }
}
