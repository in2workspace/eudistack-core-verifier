package es.in2.vcverifier.shared.config;

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

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CertificateLoginFilter extends OncePerRequestFilter {

    public static final String CLIENT_CERT_HEADER = "Client-Cert";
    public static final String CLIENT_CERT_CHAIN_HEADER = "Client-Cert-Chain";
    public static final String CERTIFICATE_LOGIN_PATH = "/api/login/certificate";

    public static boolean isCertificateLogin(HttpServletRequest request) {
        String servletPath = request.getServletPath() == null ? "" : request.getServletPath();
        String pathInfo = request.getPathInfo() == null ? "" : request.getPathInfo();
        return CERTIFICATE_LOGIN_PATH.equals(servletPath + pathInfo);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!isCertificateLogin(request) && carriesCertificate(request)) {
            log.warn("event=certificate_header_outside_certificate_login method={}", request.getMethod());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        chain.doFilter(request, response);
    }

    private static boolean carriesCertificate(HttpServletRequest request) {
        return request.getHeader(CLIENT_CERT_HEADER) != null || request.getHeader(CLIENT_CERT_CHAIN_HEADER) != null;
    }
}
