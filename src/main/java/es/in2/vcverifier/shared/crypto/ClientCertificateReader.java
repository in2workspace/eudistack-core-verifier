package es.in2.vcverifier.shared.crypto;

import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import es.in2.vcverifier.shared.domain.model.ClientCertificate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class ClientCertificateReader {

    private static final int RFC822_NAME = 1;
    private static final String SPAIN = "ES";
    private static final Pattern SEMANTIC_IDENTIFIER = Pattern.compile("^IDC([A-Z]{2})-(.+)$");
    private static final Pattern DNI = Pattern.compile("^\\d{8}[A-Z]$");
    private static final Pattern NIE = Pattern.compile("^[XYZ]\\d{7}[A-Z]$");
    private static final PersonalNumber NO_NUMBER = new PersonalNumber(null, null);

    private record PersonalNumber(String country, String number) {
    }

    public List<X509Certificate> readChain(String header) {
        if (header == null || header.isBlank()) {
            throw new IllegalArgumentException("Empty client certificate header");
        }
        String pem = URLDecoder.decode(header.replace("+", "%2B"), StandardCharsets.UTF_8);
        try {
            Collection<? extends Certificate> certificates = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
            List<X509Certificate> chain = certificates.stream()
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .toList();
            if (chain.isEmpty()) {
                throw new IllegalArgumentException("No certificate in the client certificate header");
            }
            return chain;
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Unreadable client certificate header", e);
        }
    }

    public ClientCertificate read(X509Certificate certificate) {
        X500Name subject = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        PersonalNumber number = personalNumber(attribute(subject, BCStyle.SERIALNUMBER));
        CertificateIdentity identity = new CertificateIdentity(
                attribute(subject, BCStyle.GIVENNAME),
                attribute(subject, BCStyle.SURNAME),
                attribute(subject, BCStyle.CN),
                email(certificate),
                number.country(),
                number.number());
        return new ClientCertificate(identity,
                certificate.getIssuerX500Principal().getName(),
                fingerprint(certificate),
                certificate.getNotAfter().toInstant());
    }

    private static PersonalNumber personalNumber(String serialNumber) {
        if (serialNumber == null) {
            return NO_NUMBER;
        }
        Matcher semantic = SEMANTIC_IDENTIFIER.matcher(serialNumber);
        if (semantic.matches()) {
            return new PersonalNumber(semantic.group(1), semantic.group(2));
        }
        if (DNI.matcher(serialNumber).matches() || NIE.matcher(serialNumber).matches()) {
            return new PersonalNumber(SPAIN, serialNumber);
        }
        return NO_NUMBER;
    }

    private static String attribute(X500Name name, ASN1ObjectIdentifier type) {
        RDN[] rdns = name.getRDNs(type);
        if (rdns.length == 0) {
            return null;
        }
        ASN1Encodable value = rdns[0].getFirst().getValue();
        String text = value instanceof ASN1String string ? string.getString() : value.toString();
        return text == null || text.isBlank() ? null : text.trim();
    }

    private static String email(X509Certificate certificate) {
        try {
            Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
            if (alternativeNames == null) {
                return null;
            }
            return alternativeNames.stream()
                    .filter(name -> name.size() == 2 && Integer.valueOf(RFC822_NAME).equals(name.get(0)))
                    .map(name -> name.get(1))
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .filter(value -> !value.isBlank())
                    .findFirst()
                    .orElse(null);
        } catch (CertificateParsingException _) {
            return null;
        }
    }

    private static String fingerprint(X509Certificate certificate) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException("Cannot compute the certificate fingerprint", e);
        }
    }
}
