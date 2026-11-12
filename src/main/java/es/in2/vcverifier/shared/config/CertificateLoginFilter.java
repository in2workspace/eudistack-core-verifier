package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.CertificateLoginProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CertificateLoginFilter extends OncePerRequestFilter {

    public static final String MTLS_CLIENT_CERT_HEADER = "X-Amzn-Mtls-Clientcert";
    public static final String CERTIFICATE_LOGIN_PATH = "/api/login/certificate";
    private static final String HEALTH_PATH = "/health";

    private final int certificatePort;

    public CertificateLoginFilter(CertificateLoginProperties certificateLoginProperties) {
        this.certificatePort = certificateLoginProperties.port();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = pathWithinApplication(request);
        if (request.getLocalPort() == certificatePort) {
            if (!isAllowedOnCertificatePort(request.getMethod(), path)) {
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                return;
            }
        } else if (request.getHeader(MTLS_CLIENT_CERT_HEADER) != null) {
            log.warn("event=mtls_header_outside_certificate_port method={}", request.getMethod());
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        } else if (CERTIFICATE_LOGIN_PATH.equals(path)) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        chain.doFilter(request, response);
    }

    private static boolean isAllowedOnCertificatePort(String method, String path) {
        if (CERTIFICATE_LOGIN_PATH.equals(path)) {
            return HttpMethod.POST.matches(method) || HttpMethod.OPTIONS.matches(method);
        }
        boolean health = HEALTH_PATH.equals(path) || path.startsWith(HEALTH_PATH + "/");
        return health && (HttpMethod.GET.matches(method) || HttpMethod.HEAD.matches(method));
    }

    private static String pathWithinApplication(HttpServletRequest request) {
        String servletPath = request.getServletPath() == null ? "" : request.getServletPath();
        String pathInfo = request.getPathInfo() == null ? "" : request.getPathInfo();
        return servletPath + pathInfo;
    }
}
