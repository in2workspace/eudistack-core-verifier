package es.in2.vcverifier.verifier.infrastructure.adapter.trustvalidation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import es.in2.vcverifier.verifier.domain.model.CertificateTrust;
import es.in2.vcverifier.verifier.infrastructure.config.TrustValidationProperties;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class DssCertificateTrustValidationAdapterTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-10-22T12:00:00Z");
    private static final String PASSED_WITH_QSCD = """
            {"simpleCertificateReport":{"Certificate":{"Indication":"PASSED","SubIndication":null,
            "qualificationAtValidation":"QC for eSig with QSCD"}},
            "diagnosticData":{"TrustedList":[{"LastLoading":"2026-10-22T11:00:00Z"}]}}
            """;

    private HttpServer server;
    private final AtomicReference<String> receivedBody = new AtomicReference<>();
    private volatile int status = 200;
    private volatile String responseBody = PASSED_WITH_QSCD;
    private volatile boolean answerLate;
    private final CountDownLatch releaseLateAnswer = new CountDownLatch(1);

    @BeforeEach
    void startDss() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/dss" + DssCertificateTrustValidationAdapter.VALIDATE_CERTIFICATE_PATH, exchange -> {
            receivedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            if (answerLate) {
                try {
                    releaseLateAnswer.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException _) {
                    Thread.currentThread().interrupt();
                }
            }
            byte[] body = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stopDss() {
        releaseLateAnswer.countDown();
        server.stop(0);
    }

    @Test
    void validate_sendsTheCertificateAndItsChainAndTranslatesTheReport() throws Exception {
        X509Certificate certificate = certificate(false);
        X509Certificate issuer = certificate(false);

        CertificateTrust trust = adapter(Duration.ofSeconds(5)).validate(certificate, List.of(issuer));

        assertThat(trust).isEqualTo(new CertificateTrust.Trusted(AssuranceLevel.HIGH, List.of("hwk")));
        JsonNode request = MAPPER.readTree(receivedBody.get());
        assertThat(request.at("/certificate/encodedCertificate").asText())
                .isEqualTo(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        assertThat(request.at("/certificateChain/0/encodedCertificate").asText())
                .isEqualTo(Base64.getEncoder().encodeToString(issuer.getEncoded()));
        assertThat(request.path("tokenExtractionStrategy").asText()).isEqualTo("NONE");
    }

    @Test
    void validate_certificateWithOrganizationIdentifier_isNotANaturalPerson() throws Exception {
        assertThat(adapter(Duration.ofSeconds(5)).validate(certificate(true), List.of()))
                .isEqualTo(new CertificateTrust.Rejected(CertificateLoginReason.CERTIFICATE_NOT_NATURAL_PERSON));
    }

    @Test
    void validate_errorResponse_isUnavailable() throws Exception {
        status = 500;
        responseBody = "{}";

        assertThat(adapter(Duration.ofSeconds(5)).validate(certificate(false), List.of()))
                .isEqualTo(new CertificateTrust.Rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE));
    }

    @Test
    void validate_unreadableResponse_isUnavailable() throws Exception {
        responseBody = "not json";

        assertThat(adapter(Duration.ofSeconds(5)).validate(certificate(false), List.of()))
                .isEqualTo(new CertificateTrust.Rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE));
    }

    @Test
    void validate_noAnswerWithinTheTimeout_isUnavailable() throws Exception {
        answerLate = true;

        assertThat(adapter(Duration.ofMillis(200)).validate(certificate(false), List.of()))
                .isEqualTo(new CertificateTrust.Rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE));
    }

    @Test
    void validate_serviceNotReachable_isUnavailable() throws Exception {
        server.stop(0);

        assertThat(adapter(Duration.ofSeconds(5)).validate(certificate(false), List.of()))
                .isEqualTo(new CertificateTrust.Rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE));
    }

    @Test
    void validate_withoutConfiguredUrl_isUnavailableWithoutCallingTheService() throws Exception {
        DssCertificateTrustValidationAdapter adapter = new DssCertificateTrustValidationAdapter(
                HttpClient.newHttpClient(), MAPPER, new TrustValidationProperties(" ", null, null),
                Clock.fixed(NOW, ZoneOffset.UTC));

        assertThat(adapter.validate(certificate(false), List.of()))
                .isEqualTo(new CertificateTrust.Rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE));
        assertThat(receivedBody.get()).isNull();
    }

    private DssCertificateTrustValidationAdapter adapter(Duration timeout) {
        String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/dss/";
        return new DssCertificateTrustValidationAdapter(HttpClient.newHttpClient(), MAPPER,
                new TrustValidationProperties(url, timeout, null), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static X509Certificate certificate(boolean withOrganizationIdentifier) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keyPair = generator.generateKeyPair();
        X500NameBuilder subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "GARCIA FERNANDEZ JOSE ANTONIO")
                .addRDN(BCStyle.C, "ES");
        if (withOrganizationIdentifier) {
            subject.addRDN(new ASN1ObjectIdentifier("2.5.4.97"), "VATES-A15456585");
        }
        return new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(
                subject.build(), BigInteger.ONE, Date.from(NOW.minusSeconds(3600)), Date.from(NOW.plusSeconds(3600)),
                subject.build(), keyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }
}
