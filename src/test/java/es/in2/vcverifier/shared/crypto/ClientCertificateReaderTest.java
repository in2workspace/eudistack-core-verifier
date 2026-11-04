package es.in2.vcverifier.shared.crypto;

import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import es.in2.vcverifier.shared.domain.model.ClientCertificate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientCertificateReaderTest {

    private static final Instant NOT_AFTER = Instant.parse("2028-05-01T00:00:00Z");
    private static final X500Name ISSUER = new X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, "AC FNMT Usuarios")
            .addRDN(BCStyle.O, "FNMT-RCM")
            .addRDN(BCStyle.C, "ES")
            .build();

    private final ClientCertificateReader reader = new ClientCertificateReader();

    @Test
    void read_qualifiedPersonCertificate_givesItsIdentityIssuerFingerprintAndEnd() throws Exception {
        X509Certificate certificate = personCertificate("IDCES-12345678Z", "jgarcia@example.com");

        ClientCertificate clientCertificate = reader.read(certificate);

        assertThat(clientCertificate.identity()).isEqualTo(new CertificateIdentity(
                "JOSE ANTONIO", "GARCIA FERNANDEZ", "GARCIA FERNANDEZ JOSE ANTONIO",
                "jgarcia@example.com", "ES", "12345678Z"));
        assertThat(clientCertificate.issuer()).isEqualTo("C=ES,O=FNMT-RCM,CN=AC FNMT Usuarios");
        assertThat(clientCertificate.fingerprintSha256()).isEqualTo(
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded())));
        assertThat(clientCertificate.notAfter()).isEqualTo(NOT_AFTER);
    }

    @ParameterizedTest
    @CsvSource({"IDCPT-123456789, PT, 123456789", "12345678Z, ES, 12345678Z", "X1234567L, ES, X1234567L"})
    void read_numberWithOrWithoutTheSemanticPrefix_givesItsCountryAndNumber(
            String serialNumber, String country, String number) throws Exception {
        CertificateIdentity identity = reader.read(personCertificate(serialNumber, null)).identity();

        assertThat(identity.country()).isEqualTo(country);
        assertThat(identity.personalAdministrativeNumber()).isEqualTo(number);
    }

    @ParameterizedTest
    @CsvSource({"VATES-A15456585", "1234", "idces-12345678Z"})
    void read_unrecognisedNumber_givesNoNumber(String serialNumber) throws Exception {
        CertificateIdentity identity = reader.read(personCertificate(serialNumber, null)).identity();

        assertThat(identity.country()).isNull();
        assertThat(identity.personalAdministrativeNumber()).isNull();
    }

    @Test
    void read_certificateWithoutEmailNorSerialNumber_leavesThemEmpty() throws Exception {
        CertificateIdentity identity = reader.read(personCertificate(null, null)).identity();

        assertThat(identity.email()).isNull();
        assertThat(identity.personalAdministrativeNumber()).isNull();
        assertThat(identity.commonName()).isEqualTo("GARCIA FERNANDEZ JOSE ANTONIO");
    }

    @Test
    void read_neverPrintsThePersonalNumber() throws Exception {
        ClientCertificate clientCertificate = reader.read(personCertificate("IDCES-12345678Z", "jgarcia@example.com"));

        assertThat(clientCertificate.toString()).doesNotContain("12345678Z", "jgarcia@example.com", "GARCIA");
    }

    @Test
    void readChain_urlEncodedPemChain_givesTheCertificatesInOrder() throws Exception {
        X509Certificate leaf = personCertificate("IDCES-12345678Z", null);
        X509Certificate issuer = personCertificate(null, null);

        List<X509Certificate> chain = reader.readChain(albHeader(pem(leaf) + pem(issuer)));

        assertThat(chain).containsExactly(leaf, issuer);
    }

    @Test
    void readChain_pemWithUnencodedPlusSigns_isStillRead() throws Exception {
        X509Certificate leaf = personCertificate("IDCES-12345678Z", null);
        String header = albHeader(pem(leaf)).replace("%2B", "+");

        assertThat(reader.readChain(header)).containsExactly(leaf);
    }

    @Test
    void readChain_unreadableHeader_failsWithoutEchoingIt() {
        assertThatThrownBy(() -> reader.readChain("-----BEGIN%20CERTIFICATE-----%0Asecret-value%0A"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageNotContaining("secret-value");
        assertThatThrownBy(() -> reader.readChain(" "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static X509Certificate personCertificate(String serialNumber, String email) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keyPair = generator.generateKeyPair();
        X500NameBuilder subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.SURNAME, "GARCIA FERNANDEZ")
                .addRDN(BCStyle.GIVENNAME, "JOSE ANTONIO")
                .addRDN(BCStyle.CN, "GARCIA FERNANDEZ JOSE ANTONIO");
        if (serialNumber != null) {
            subject.addRDN(BCStyle.SERIALNUMBER, serialNumber);
        }
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(ISSUER, BigInteger.valueOf(System.nanoTime()),
                Date.from(NOT_AFTER.minus(700, ChronoUnit.DAYS)), Date.from(NOT_AFTER), subject.build(), keyPair.getPublic());
        if (email != null) {
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.rfc822Name, email)));
        }
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }

    private static String albHeader(String pem) {
        return URLEncoder.encode(pem, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String pem(X509Certificate certificate) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }
}
