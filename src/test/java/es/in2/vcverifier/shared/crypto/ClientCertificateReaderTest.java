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

    private static final List<String> NO_CHAIN = List.of();
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
    void readChain_certificateWithoutChain_givesOnlyTheCertificate() throws Exception {
        X509Certificate leaf = personCertificate("IDCES-12345678Z", null);

        assertThat(reader.readChain(byteSequence(leaf), List.of())).containsExactly(leaf);
    }

    @Test
    void readChain_chainAsAList_givesTheCertificatesInOrder() throws Exception {
        X509Certificate leaf = personCertificate("IDCES-12345678Z", null);
        X509Certificate intermediate = personCertificate(null, null);
        X509Certificate root = personCertificate(null, null);

        List<X509Certificate> chain = reader.readChain(byteSequence(leaf),
                List.of(byteSequence(intermediate) + ", " + byteSequence(root)));

        assertThat(chain).containsExactly(leaf, intermediate, root);
    }

    @Test
    void readChain_longestChainCloudFrontForwards_isRead() throws Exception {
        X509Certificate leaf = personCertificate("IDCES-12345678Z", null);
        String member = byteSequence(personCertificate(null, null));

        assertThat(reader.readChain(byteSequence(leaf), List.of(member + "," + member, member))).hasSize(4);
    }

    @Test
    void readChain_longerChain_failsBeforeReadingIt() throws Exception {
        String leaf = byteSequence(personCertificate("IDCES-12345678Z", null));

        List<String> fiveCertificates = List.of(":a:, :b:", ":c:, :d:");

        assertThatThrownBy(() -> reader.readChain(leaf, fiveCertificates))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Client certificate chain has more than 4 certificates");
    }

    @Test
    void readChain_chainSplitInSeveralHeaders_keepsTheirOrder() throws Exception {
        X509Certificate leaf = personCertificate("IDCES-12345678Z", null);
        X509Certificate intermediate = personCertificate(null, null);
        X509Certificate root = personCertificate(null, null);

        List<X509Certificate> chain = reader.readChain(" " + byteSequence(leaf) + " ",
                List.of(byteSequence(intermediate), byteSequence(root)));

        assertThat(chain).containsExactly(leaf, intermediate, root);
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "MIIBsecretvalue | not a byte sequence",
            ":MIIB secret-value: | not base64",
            ":c2VjcmV0LXZhbHVl: | not an X.509 certificate",
            ": | not a byte sequence"
    })
    void readChain_unreadableCertificate_failsSayingWhyWithoutEchoingIt(String header, String reason) {
        assertThatThrownBy(() -> reader.readChain(header, NO_CHAIN))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(reason)
                .hasMessageNotContaining("secret")
                .hasMessageNotContaining("c2VjcmV0");
    }

    @Test
    void readChain_unreadableChainMember_fails() throws Exception {
        String leaf = byteSequence(personCertificate("IDCES-12345678Z", null));

        List<String> notACertificate = List.of(":c2VjcmV0LXZhbHVl:");
        List<String> emptyMember = List.of(leaf + ",");

        assertThatThrownBy(() -> reader.readChain(leaf, notACertificate))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> reader.readChain(leaf, emptyMember))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void readChain_withoutCertificate_fails() {
        assertThatThrownBy(() -> reader.readChain(null, NO_CHAIN))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> reader.readChain(" ", NO_CHAIN))
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

    private static String byteSequence(X509Certificate certificate) throws Exception {
        return ":" + Base64.getEncoder().encodeToString(certificate.getEncoded()) + ":";
    }
}
