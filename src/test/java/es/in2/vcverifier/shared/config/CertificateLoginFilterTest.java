package es.in2.vcverifier.shared.config;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class CertificateLoginFilterTest {

    private static final String LOGIN_PATH = "/api/login/certificate";
    private static final String CERTIFICATE = ":MIIB:";

    private final CertificateLoginFilter filter = new CertificateLoginFilter();

    @ParameterizedTest
    @ValueSource(strings = {"POST", "OPTIONS"})
    void certificateLogin_withTheCertificateHeaders_isLetThrough(String method) throws Exception {
        MockHttpServletRequest request = request(method, LOGIN_PATH);
        request.addHeader(CertificateLoginFilter.CLIENT_CERT_HEADER, CERTIFICATE);
        request.addHeader(CertificateLoginFilter.CLIENT_CERT_CHAIN_HEADER, ":MIIC:");

        assertLetThrough(request);
    }

    @Test
    void certificateLogin_withoutCertificate_isLetThrough() throws Exception {
        assertLetThrough(request("POST", LOGIN_PATH));
    }

    @ParameterizedTest
    @CsvSource({
            "GET, /oidc/authorize, Client-Cert",
            "POST, /oidc/token, Client-Cert",
            "POST, /api/login/wallet, Client-Cert-Chain",
            "GET, /health, Client-Cert",
            "POST, /api/login/certificate/x, Client-Cert"
    })
    void otherPath_withACertificateHeader_isForbidden(String method, String path, String header) throws Exception {
        MockHttpServletRequest request = request(method, path);
        request.addHeader(header, CERTIFICATE);

        assertForbidden(request);
    }

    @Test
    void otherPath_withoutTheCertificateHeader_isLetThrough() throws Exception {
        assertLetThrough(request("GET", "/api/login/methods"));
    }

    @Test
    void isCertificateLogin_matchesOnlyTheCertificateLoginPath() {
        assertThat(CertificateLoginFilter.isCertificateLogin(request("POST", LOGIN_PATH))).isTrue();
        assertThat(CertificateLoginFilter.isCertificateLogin(request("POST", "/api/login/wallet"))).isFalse();
        assertThat(CertificateLoginFilter.isCertificateLogin(request("POST", LOGIN_PATH + "/"))).isFalse();
    }

    private void assertLetThrough(MockHttpServletRequest request) throws Exception {
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(200);
    }

    private void assertForbidden(MockHttpServletRequest request) throws Exception {
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
