package es.in2.vcverifier.verifier.infrastructure.adapter.trustvalidation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.verifier.domain.model.IssuerTrust;
import es.in2.vcverifier.verifier.infrastructure.config.TrustValidationProperties;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class DssIssuerTrustValidationAdapterTest {

    private static final Instant NOW = Instant.parse("2026-11-23T12:00:00Z");
    private static final String TYPE = "learcredential.employee.sd.1";
    private static final String ISSUER = "VATES-B00000000";

    private final DssCertificateValidationClient client = mock(DssCertificateValidationClient.class);
    private DssIssuerTrustValidationAdapter adapter;
    private JsonNode issuerInIssuersList;

    @BeforeEach
    void setUp() throws Exception {
        adapter = new DssIssuerTrustValidationAdapter(client, new TrustValidationProperties("http://dss", null, null),
                Clock.fixed(NOW, ZoneOffset.UTC));
        try (InputStream in = getClass().getResourceAsStream("/dss/issuer-in-issuers-list.json")) {
            issuerInIssuersList = new ObjectMapper().readTree(in);
        }
    }

    @Test
    void validate_sendsTheFirstCertificateAndTheRestAsChainAndTranslatesTheReport() throws Exception {
        X509Certificate leaf = certificate("CN=Sello emisor de prueba");
        X509Certificate intermediate = certificate("CN=Intermedia");
        when(client.validateCertificate(any(), any())).thenReturn(issuerInIssuersList);

        IssuerTrust trust = adapter.validate(List.of(leaf, intermediate), TYPE, ISSUER);

        assertThat(trust).isInstanceOf(IssuerTrust.Trusted.class);
        verify(client).validateCertificate(leaf, List.of(intermediate));
    }

    @Test
    void validate_withoutIssuerChain_isNotTrustedWithoutCallingTheService() {
        assertThat(adapter.validate(List.of(), TYPE, ISSUER)).isInstanceOf(IssuerTrust.NotTrusted.class);
        verifyNoInteractions(client);
    }

    @Test
    void validate_withoutAttestationType_isNotTrustedWithoutCallingTheService() throws Exception {
        assertThat(adapter.validate(List.of(certificate("CN=x")), " ", ISSUER))
                .isInstanceOf(IssuerTrust.NotTrusted.class);
        verifyNoInteractions(client);
    }

    @Test
    void validate_serviceUnavailable_isUnavailable() throws Exception {
        when(client.validateCertificate(any(), any())).thenThrow(new DssUnavailableException("timeout"));

        assertThat(adapter.validate(List.of(certificate("CN=x")), TYPE, ISSUER))
                .isInstanceOf(IssuerTrust.Unavailable.class);
    }

    private static X509Certificate certificate(String subject) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keyPair = generator.generateKeyPair();
        X500Name name = new X500Name(subject);
        return new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, Date.from(NOW.minusSeconds(3600)), Date.from(NOW.plusSeconds(3600)),
                name, keyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }
}
