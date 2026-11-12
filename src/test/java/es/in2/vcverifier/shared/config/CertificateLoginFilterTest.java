package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.CertificateLoginProperties;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class CertificateLoginFilterTest {

    private static final int NORMAL_PORT = 8080;
    private static final int CERTIFICATE_PORT = 8081;

    private final CertificateLoginFilter filter =
            new CertificateLoginFilter(new CertificateLoginProperties(CERTIFICATE_PORT, null));

    @ParameterizedTest
    @CsvSource({
            "POST, /api/login/certificate",
            "OPTIONS, /api/login/certificate",
            "GET, /health",
            "GET, /health/liveness",
            "HEAD, /health"
    })
    void certificatePort_letsThroughTheCertificateLoginAndHealth(String method, String path) throws Exception {
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request(CERTIFICATE_PORT, method, path), response, chain);

        verify(chain).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @ParameterizedTest
    @CsvSource({
            "GET, /api/login/certificate",
            "POST, /oidc/token",
            "GET, /oidc/authorize",
            "GET, /api/login/methods",
            "POST, /api/login/wallet",
            "GET, /.well-known/openid-configuration",
            "POST, /health",
            "GET, /healthz"
    })
    void certificatePort_answersNotFoundToEverythingElse(String method, String path) throws Exception {
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request(CERTIFICATE_PORT, method, path), response, chain);

        verify(chain, never()).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void certificatePort_acceptsTheCertificateHeader() throws Exception {
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletRequest request = request(CERTIFICATE_PORT, "POST", "/api/login/certificate");
        request.addHeader(CertificateLoginFilter.MTLS_CLIENT_CERT_HEADER, "-----BEGIN%20CERTIFICATE-----");

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        verify(chain).doFilter(any(), any());
    }

    @ParameterizedTest
    @CsvSource({
            "GET, /oidc/authorize",
            "POST, /oidc/token",
            "GET, /health"
    })
    void normalPort_rejectsAnyRequestWithTheCertificateHeader(String method, String path) throws Exception {
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpServletRequest request = request(NORMAL_PORT, method, path);
        request.addHeader(CertificateLoginFilter.MTLS_CLIENT_CERT_HEADER, "-----BEGIN%20CERTIFICATE-----");

        filter.doFilter(request, response, chain);

        verify(chain, never()).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void normalPort_hasNoCertificateLogin() throws Exception {
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request(NORMAL_PORT, "POST", "/api/login/certificate"), response, chain);

        verify(chain, never()).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void normalPort_letsTheRestThrough() throws Exception {
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request(NORMAL_PORT, "GET", "/api/login/methods"), new MockHttpServletResponse(), chain);

        verify(chain).doFilter(any(), any());
    }

    private static MockHttpServletRequest request(int localPort, String method, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, "/verifier" + path);
        request.setContextPath("/verifier");
        request.setServletPath(path);
        request.setLocalPort(localPort);
        return request;
    }
}
