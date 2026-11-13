package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.CertificateLoginProperties;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class CertificateLoginFilterTest {

    private static final String SECURE_ORIGIN = "s3cr3t-0f-th3-s3cur3-0r1g1n-d1str1but10n";
    private static final String LOGIN_PATH = "/api/login/certificate";
    private static final String CERTIFICATE = ":MIIB:";

    private final CertificateLoginFilter filter = new CertificateLoginFilter(new CertificateLoginProperties(
            SECURE_ORIGIN, Map.of("cgcom", new CertificateLoginProperties.Tenant("https://cgcom.example.com"))));

    @ParameterizedTest
    @ValueSource(strings = {"POST", "OPTIONS"})
    void certificateLogin_fromTheSecureOrigin_isLetThrough(String method) throws Exception {
        MockHttpServletRequest request = request(method, LOGIN_PATH);
        request.addHeader(CertificateLoginFilter.SECURE_ORIGIN_HEADER, SECURE_ORIGIN);
        request.addHeader(CertificateLoginFilter.CLIENT_CERT_HEADER, CERTIFICATE);
        request.addHeader(CertificateLoginFilter.CLIENT_CERT_CHAIN_HEADER, ":MIIC:");

        assertLetThrough(filter, request);
    }

    @Test
    void certificateLogin_fromTheSecureOriginWithoutCertificate_isLetThrough() throws Exception {
        MockHttpServletRequest request = request("POST", LOGIN_PATH);
        request.addHeader(CertificateLoginFilter.SECURE_ORIGIN_HEADER, SECURE_ORIGIN);

        assertLetThrough(filter, request);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "wrong", SECURE_ORIGIN + "x", "S3CR3T-0F-TH3-S3CUR3-0R1G1N-D1STR1BUT10N"})
    void certificateLogin_withAWrongSecureOrigin_isForbidden(String secureOrigin) throws Exception {
        MockHttpServletRequest request = request("POST", LOGIN_PATH);
        request.addHeader(CertificateLoginFilter.SECURE_ORIGIN_HEADER, secureOrigin);
        request.addHeader(CertificateLoginFilter.CLIENT_CERT_HEADER, CERTIFICATE);

        assertForbidden(filter, request);
    }

    @Test
    void certificateLogin_withoutSecureOrigin_isForbidden() throws Exception {
        MockHttpServletRequest request = request("POST", LOGIN_PATH);
        request.addHeader(CertificateLoginFilter.CLIENT_CERT_HEADER, CERTIFICATE);

        assertForbidden(filter, request);
    }

    @Test
    void certificateLogin_withoutConfiguredSecureOrigin_isAlwaysForbidden() throws Exception {
        CertificateLoginFilter unconfigured = new CertificateLoginFilter(new CertificateLoginProperties(null, null));
        MockHttpServletRequest request = request("POST", LOGIN_PATH);
        request.addHeader(CertificateLoginFilter.SECURE_ORIGIN_HEADER, "");

        assertForbidden(unconfigured, request);
    }

    @ParameterizedTest
    @CsvSource({
            "GET, /oidc/authorize, Client-Cert",
            "POST, /oidc/token, Client-Cert",
            "POST, /api/login/wallet, Client-Cert-Chain",
            "GET, /health, Client-Cert",
            "POST, /api/login/certificate/x, Client-Cert"
    })
    void otherPath_withACertificateHeader_isForbiddenEvenFromTheSecureOrigin(String method, String path, String header)
            throws Exception {
        MockHttpServletRequest request = request(method, path);
        request.addHeader(CertificateLoginFilter.SECURE_ORIGIN_HEADER, SECURE_ORIGIN);
        request.addHeader(header, CERTIFICATE);

        assertForbidden(filter, request);
    }

    @Test
    void otherPath_withoutTheCertificateHeader_isLetThrough() throws Exception {
        assertLetThrough(filter, request("GET", "/api/login/methods"));
    }

    @Test
    void isCertificateLogin_matchesOnlyTheCertificateLoginPath() {
        assertThat(CertificateLoginFilter.isCertificateLogin(request("POST", LOGIN_PATH))).isTrue();
        assertThat(CertificateLoginFilter.isCertificateLogin(request("POST", "/api/login/wallet"))).isFalse();
        assertThat(CertificateLoginFilter.isCertificateLogin(request("POST", LOGIN_PATH + "/"))).isFalse();
    }

    private static void assertLetThrough(CertificateLoginFilter filter, MockHttpServletRequest request)
            throws Exception {
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(200);
    }

    private static void assertForbidden(CertificateLoginFilter filter, MockHttpServletRequest request)
            throws Exception {
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain, never()).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsByteArray()).isEmpty();
        assertThat(response.getHeaderNames()).isEmpty();
    }

    private static MockHttpServletRequest request(String method, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, "/verifier" + path);
        request.setContextPath("/verifier");
        request.setServletPath(path);
        return request;
    }
}
