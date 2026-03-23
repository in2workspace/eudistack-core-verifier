package es.in2.vcverifier.shared.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * SEC-F2: Adds security response headers to every HTTP response.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class SecurityHeadersFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (response instanceof HttpServletResponse httpResponse) {
            httpResponse.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
            httpResponse.setHeader("X-Content-Type-Options", "nosniff");
            httpResponse.setHeader("X-Frame-Options", "DENY");
            httpResponse.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
            httpResponse.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
            httpResponse.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
            // Cache-Control: no-store only for non-public endpoints (JWKS/.well-known can be cached)
            String path = request instanceof jakarta.servlet.http.HttpServletRequest httpReq
                    ? httpReq.getRequestURI() : "";
            if (!path.startsWith("/oidc/jwks") && !path.startsWith("/.well-known")) {
                httpResponse.setHeader("Cache-Control", "no-store");
            }
        }

        chain.doFilter(request, response);
    }
}
