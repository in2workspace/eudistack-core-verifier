package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.CertificateLoginProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CertificateLoginFilter extends OncePerRequestFilter {

    public static final String CLIENT_CERT_HEADER = "Client-Cert";
    public static final String CLIENT_CERT_CHAIN_HEADER = "Client-Cert-Chain";
    public static final String SECURE_ORIGIN_HEADER = "X-Secure-Origin";
    public static final String CERTIFICATE_LOGIN_PATH = "/api/login/certificate";

    private final byte[] secureOrigin;

    public CertificateLoginFilter(CertificateLoginProperties certificateLoginProperties) {
        String configured = certificateLoginProperties.secureOrigin();
        this.secureOrigin = configured == null ? new byte[0] : configured.getBytes(StandardCharsets.UTF_8);
    }

    public static boolean isCertificateLogin(HttpServletRequest request) {
        String servletPath = request.getServletPath() == null ? "" : request.getServletPath();
        String pathInfo = request.getPathInfo() == null ? "" : request.getPathInfo();
        return CERTIFICATE_LOGIN_PATH.equals(servletPath + pathInfo);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        boolean certificateLogin = isCertificateLogin(request);
        if (certificateLogin ? !fromSecureOrigin(request) : carriesCertificate(request)) {
            log.warn("event=certificate_login_forbidden method={} certificateLoginPath={}",
                    request.getMethod(), certificateLogin);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        chain.doFilter(request, response);
    }

    private boolean fromSecureOrigin(HttpServletRequest request) {
        String presented = request.getHeader(SECURE_ORIGIN_HEADER);
        return secureOrigin.length > 0 && presented != null
                && MessageDigest.isEqual(secureOrigin, presented.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean carriesCertificate(HttpServletRequest request) {
        return request.getHeader(CLIENT_CERT_HEADER) != null || request.getHeader(CLIENT_CERT_CHAIN_HEADER) != null;
    }
}
