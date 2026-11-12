package es.in2.vcverifier.integration;

import es.in2.vcverifier.shared.config.CertificateLoginFilter;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.concurrent.ThreadLocalRandom;

import static es.in2.vcverifier.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.flyway.enabled=false",
        "verifier.certificate-login.secure-origin=" + CertificateLoginHeaderSizeIT.SECURE_ORIGIN,
        "verifier.certificate-login.tenants.cgcom.login-origin=" + CertificateLoginHeaderSizeIT.LOGIN_ORIGIN,
        "verifier.certificate-login.subject-key=0123456789abcdef0123456789abcdef"
})
@ActiveProfiles("test")
class CertificateLoginHeaderSizeIT {

    static final String SECURE_ORIGIN = "test-secure-origin-0123456789abcdef0123";
    static final String LOGIN_ORIGIN = "https://cgcom.example.com";
    private static final int LARGEST_FNMT_PERSON_CERTIFICATE = 2_798;
    private static final int LARGEST_FNMT_INTERMEDIATE = 2_039;
    private static final int FNMT_ROOT = 1_415;
    private static final int CLOUDFRONT_AND_BROWSER_HEADERS = 3_000;

    @LocalServerPort
    private int port;

    @Value("${server.servlet.context-path:}")
    private String contextPath;

    @MockitoBean
    private RegisteredClientRepository registeredClientRepository;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    private final HttpClient client = HttpClient.newHttpClient();

    @Test
    void certificateWithTheLongestChainCloudFrontForwards_reachesTheCertificateLogin() throws Exception {
        HttpResponse<String> response = client.send(certificateLogin()
                        .header(CertificateLoginFilter.CLIENT_CERT_HEADER, byteSequence(LARGEST_FNMT_PERSON_CERTIFICATE))
                        .header(CertificateLoginFilter.CLIENT_CERT_CHAIN_HEADER, byteSequence(LARGEST_FNMT_INTERMEDIATE)
                                + ", " + byteSequence(LARGEST_FNMT_INTERMEDIATE) + ", " + byteSequence(FNMT_ROOT))
                        .header("CloudFront-Viewer-Cert-Subject", "x".repeat(CLOUDFRONT_AND_BROWSER_HEADERS))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(404);
        assertThat(response.body()).contains("login_not_found");
    }

    private HttpRequest.Builder certificateLogin() {
        return HttpRequest.newBuilder(URI.create("http://localhost:" + port + contextPath + "/api/login/certificate"))
                .header(CertificateLoginFilter.SECURE_ORIGIN_HEADER, SECURE_ORIGIN)
                .header(X_TENANT_HEADER, "cgcom")
                .header("Origin", LOGIN_ORIGIN)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"state\":\"unknown\"}"));
    }

    private static String byteSequence(int derLength) {
        byte[] der = new byte[derLength];
        ThreadLocalRandom.current().nextBytes(der);
        return ":" + Base64.getEncoder().encodeToString(der) + ":";
    }
}
