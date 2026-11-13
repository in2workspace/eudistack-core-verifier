package es.in2.vcverifier.integration.support;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

public final class TestCertificates {

    private static final ASN1ObjectIdentifier ORGANIZATION_IDENTIFIER = new ASN1ObjectIdentifier("2.5.4.97");
    private static final ASN1ObjectIdentifier QC_STATEMENTS = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3");
    private static final ASN1ObjectIdentifier QC_COMPLIANCE = new ASN1ObjectIdentifier("0.4.0.1862.1.1");
    private static final ASN1ObjectIdentifier QC_SSCD = new ASN1ObjectIdentifier("0.4.0.1862.1.4");
    private static final ASN1ObjectIdentifier QC_TYPE = new ASN1ObjectIdentifier("0.4.0.1862.1.6");
    private static final ASN1ObjectIdentifier QC_TYPE_ESIGN = new ASN1ObjectIdentifier("0.4.0.1862.1.6.1");
    private static final X500Name CA_NAME = new X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.C, "ES")
            .addRDN(BCStyle.O, "EUDIStack Test")
            .addRDN(BCStyle.CN, "EUDIStack Test Person CA")
            .build();
    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());
    private static final KeyPair CA_KEYS = keyPair();

    private TestCertificates() {
    }

    public record Person(String number, String givenName, String surname, String email) {

        public String commonName() {
            return surname + " " + givenName + " - " + number;
        }
    }

    public static X509Certificate naturalPerson(Person person, boolean qscd) {
        return issue(subject(person).build(), person.email(), qscd, Instant.now().plus(365, ChronoUnit.DAYS));
    }

    public static X509Certificate representative(Person person, String organizationIdentifier) {
        X500Name subject = subject(person)
                .addRDN(ORGANIZATION_IDENTIFIER, organizationIdentifier)
                .addRDN(BCStyle.O, "ENTIDAD DE PRUEBAS")
                .build();
        return issue(subject, person.email(), false, Instant.now().plus(365, ChronoUnit.DAYS));
    }

    public static X509Certificate expired(Person person) {
        return issue(subject(person).build(), person.email(), false, Instant.now().minus(1, ChronoUnit.DAYS));
    }

    public static X509Certificate selfSigned(Person person) {
        KeyPair keys = keyPair();
        X500Name subject = subject(person).build();
        return build(subject, subject, keys, keys.getPrivate(), person.email(), false,
                Instant.now().plus(365, ChronoUnit.DAYS));
    }

    public static String header(X509Certificate certificate) {
        return ":" + base64(certificate) + ":";
    }

    public static String base64(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X500NameBuilder subject(Person person) {
        return new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.SERIALNUMBER, "IDCES-" + person.number())
                .addRDN(BCStyle.GIVENNAME, person.givenName())
                .addRDN(BCStyle.SURNAME, person.surname())
                .addRDN(BCStyle.CN, person.commonName());
    }

    private static X509Certificate issue(X500Name subject, String email, boolean qscd, Instant notAfter) {
        return build(CA_NAME, subject, keyPair(), CA_KEYS.getPrivate(), email, qscd, notAfter);
    }

    private static X509Certificate build(X500Name issuer, X500Name subject, KeyPair subjectKeys, PrivateKey signer,
                                         String email, boolean qscd, Instant notAfter) {
        try {
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer,
                    BigInteger.valueOf(SERIAL.incrementAndGet()), Date.from(notAfter.minus(700, ChronoUnit.DAYS)),
                    Date.from(notAfter), subject, subjectKeys.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            builder.addExtension(QC_STATEMENTS, false, qcStatements(qscd));
            if (email != null) {
                builder.addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.rfc822Name, email)));
            }
            return new JcaX509CertificateConverter().getCertificate(
                    builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer)));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot build the test certificate", e);
        }
    }

    private static DERSequence qcStatements(boolean qscd) {
        ASN1EncodableVector statements = new ASN1EncodableVector();
        statements.add(new DERSequence(QC_COMPLIANCE));
        if (qscd) {
            statements.add(new DERSequence(QC_SSCD));
        }
        ASN1EncodableVector type = new ASN1EncodableVector();
        type.add(QC_TYPE);
        type.add(new DERSequence(QC_TYPE_ESIGN));
        statements.add(new DERSequence(type));
        return new DERSequence(statements);
    }

    private static KeyPair keyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
