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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class ClientCertificateReader {

    public static final int MAX_CHAIN_LENGTH = 4;
    private static final int RFC822_NAME = 1;
    private static final String SPAIN = "ES";
    private static final Pattern SEMANTIC_IDENTIFIER = Pattern.compile("^IDC([A-Z]{2})-(.+)$");
    private static final Pattern DNI = Pattern.compile("^\\d{8}[A-Z]$");
    private static final Pattern NIE = Pattern.compile("^[XYZ]\\d{7}[A-Z]$");
    private static final PersonalNumber NO_NUMBER = new PersonalNumber(null, null);

    private record PersonalNumber(String country, String number) {
    }

    public List<X509Certificate> readChain(String clientCert, List<String> clientCertChain) {
        if (clientCert == null || clientCert.isBlank()) {
            throw new IllegalArgumentException("No client certificate header");
        }
        List<String> members = new ArrayList<>();
        members.add(clientCert);
        for (String header : clientCertChain) {
            members.addAll(List.of(header.split(",", -1)));
        }
        if (members.size() > MAX_CHAIN_LENGTH) {
            throw new IllegalArgumentException("Client certificate chain has more than " + MAX_CHAIN_LENGTH
                    + " certificates");
        }
        return members.stream().map(member -> certificate(member.strip())).toList();
    }

    private static X509Certificate certificate(String byteSequence) {
        if (byteSequence.length() < 2 || byteSequence.charAt(0) != ':'
                || byteSequence.charAt(byteSequence.length() - 1) != ':') {
            throw new IllegalArgumentException("Client certificate header member is not a byte sequence");
        }
        byte[] der;
        try {
            der = Base64.getDecoder().decode(byteSequence.substring(1, byteSequence.length() - 1));
        } catch (IllegalArgumentException _) {
            throw new IllegalArgumentException("Client certificate header member is not base64");
        }
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException | ClassCastException _) {
            throw new IllegalArgumentException("Client certificate header member is not an X.509 certificate");
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
