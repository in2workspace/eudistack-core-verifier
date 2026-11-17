package es.in2.vcverifier.oauth2.domain.service;

import es.in2.vcverifier.shared.crypto.ClientCertificateReader;
import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

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
                        entry("name", "JOSE ANTONIO GARCIA FERNANDEZ"));
    }

    @ParameterizedTest
    @CsvSource({
            "GARCIA FERNANDEZ JOSE ANTONIO - 12345678Z, GARCIA FERNANDEZ JOSE ANTONIO",
            "GARCIA FERNANDEZ JOSE ANTONIO - DNI 12345678Z, GARCIA FERNANDEZ JOSE ANTONIO",
            "GARCIA-PEREZ JOSE - OTRO - 12345678Z, GARCIA-PEREZ JOSE - OTRO",
            "GARCIA-PEREZ JOSE, GARCIA-PEREZ JOSE",
            "GARCIA FERNANDEZ JOSE ANTONIO - OTRO, GARCIA FERNANDEZ JOSE ANTONIO - OTRO"})
    void forScopes_profileWithoutGivenNameOrSurname_givesTheCommonNameWithoutTheNumber(
            String commonName, String name) {
        CertificateIdentity withoutNames = new CertificateIdentity(
                null, "GARCIA FERNANDEZ", commonName, null, "ES", "12345678Z");

        assertThat(CertificateClaims.forScopes(withoutNames, Set.of("profile")))
                .containsEntry("name", name);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("certificatesOfEachProvider")
    void forScopes_profile_neverPutsTheNumberInTheName(String provider, X500Name subject, String name, String number)
            throws Exception {
        CertificateIdentity identity = new ClientCertificateReader().read(certificate(subject)).identity();

        assertThat(CertificateClaims.forScopes(identity, Set.of("openid", "profile")))
                .containsEntry("name", name)
                .allSatisfy((claim, value) -> assertThat(value.toString()).doesNotContain(number));
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

    private static Stream<Arguments> certificatesOfEachProvider() {
        return Stream.of(
                Arguments.of("FNMT", subject("IDCES-99949991H", "NOM UN O", "ESPECIMEN UÑO ESPECIMEN DE LOS GÜENOS",
                                "ESPECIMEN UÑO ESPECIMEN DE LOS GÜENOS NOM UN O - 99949991H"),
                        "NOM UN O ESPECIMEN UÑO ESPECIMEN DE LOS GÜENOS", "99949991H"),
                Arguments.of("FNMT empleado público", subject("IDCES-99949991H", "NOM UN O",
                                "ESPECIMEN UÑO ESPECIMEN DE LOS GÜENOS",
                                "ESPECIMEN UÑO ESPECIMEN DE LOS GÜENOS NOM UN O - DNI 99949991H"),
                        "NOM UN O ESPECIMEN UÑO ESPECIMEN DE LOS GÜENOS", "99949991H"),
                Arguments.of("DNIe", subject("00000000T", "Ciudadano", "Ficticio",
                                "Ficticio Activo, Ciudadano (AUTENTICACION)"),
                        "Ciudadano Ficticio", "00000000T"),
                Arguments.of("UANATACA", subject("IDCES-12345678Z", "JOSE ANTONIO", "GARCIA FERNANDEZ",
                                "JOSE ANTONIO GARCIA FERNANDEZ"),
                        "JOSE ANTONIO GARCIA FERNANDEZ", "12345678Z"));
    }

    private static X500Name subject(String serialNumber, String givenName, String surname, String commonName) {
        return new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.SERIALNUMBER, serialNumber)
                .addRDN(BCStyle.SURNAME, surname)
                .addRDN(BCStyle.GIVENNAME, givenName)
                .addRDN(BCStyle.CN, commonName)
                .build();
    }

    private static X509Certificate certificate(X500Name subject) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keyPair = generator.generateKeyPair();
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, BigInteger.valueOf(System.nanoTime()),
                Date.from(now.minus(1, ChronoUnit.DAYS)), Date.from(now.plus(365, ChronoUnit.DAYS)), subject,
                keyPair.getPublic());
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }
}
