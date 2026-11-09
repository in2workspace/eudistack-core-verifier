package es.in2.vcverifier.integration.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public final class DssStub implements AutoCloseable {

    public static final String PATH = "/services/rest/certificate-validation/validateCertificate";

    public record Report(String indication, String subIndication, String qualification) {

        public static Report qualified(String qualification) {
            return new Report("PASSED", null, qualification);
        }

        public static Report indeterminate(String subIndication) {
            return new Report("INDETERMINATE", subIndication, "N/A");
        }
    }

    public static final Report QC_WITH_QSCD = Report.qualified("QC for eSig with QSCD");
    public static final Report QC = Report.qualified("QC for eSig");
    public static final Report REVOKED = Report.indeterminate("REVOKED_NO_POE");
    public static final Report EXPIRED = Report.indeterminate("OUT_OF_BOUNDS_NOT_REVOKED");
    public static final Report NO_CHAIN = Report.indeterminate("NO_CERTIFICATE_CHAIN_FOUND");

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, Report> reports = new ConcurrentHashMap<>();
    private final AtomicBoolean available = new AtomicBoolean(true);
    private final AtomicInteger calls = new AtomicInteger();
    private final HttpServer server;

    public DssStub() {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        server.createContext(PATH, this::handle);
        server.start();
    }

    public String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    public X509Certificate answer(X509Certificate certificate, Report report) {
        reports.put(TestCertificates.base64(certificate), report);
        return certificate;
    }

    public void unavailable(boolean unavailable) {
        available.set(!unavailable);
    }

    public int calls() {
        return calls.get();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        calls.incrementAndGet();
        try (exchange) {
            if (!available.get()) {
                exchange.sendResponseHeaders(503, -1);
                return;
            }
            JsonNode request = objectMapper.readTree(exchange.getRequestBody());
            String certificate = request.path("certificate").path("encodedCertificate").asText();
            byte[] body = objectMapper.writeValueAsBytes(response(reports.getOrDefault(certificate, NO_CHAIN)));
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(body);
            }
        }
    }

    private ObjectNode response(Report report) {
        ObjectNode response = objectMapper.createObjectNode();
        ObjectNode certificate = response.putObject("simpleCertificateReport").putObject("Certificate");
        certificate.put("Indication", report.indication());
        if (report.subIndication() != null) {
            certificate.put("SubIndication", report.subIndication());
        }
        certificate.put("qualificationAtValidation", report.qualification());
        response.putObject("diagnosticData").putArray("TrustedList").addObject()
                .put("CountryCode", "ES")
                .put("LastLoading", Instant.now().toString());
        return response;
    }
}
