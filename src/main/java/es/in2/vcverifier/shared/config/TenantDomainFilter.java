package es.in2.vcverifier.shared.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static es.in2.vcverifier.shared.domain.util.Constants.X_TENANT_HEADER;

/**
 * Extracts the tenant identifier from the request hostname and stores it
 * as a request attribute. Atlassian-style: tenant is the first segment.
 *
 * <p>After {@code ForwardedHeaderFilter} has processed X-Forwarded-Host,
 * {@code request.getServerName()} returns the original public hostname.
 * <ul>
 *   <li>{@code kpmg.eudistack.net} → {@code kpmg}</li>
 *   <li>{@code dome.127.0.0.1.nip.io} → {@code dome}</li>
 * </ul>
 *
 * <p>Read the tenant elsewhere via:
 * {@code request.getAttribute(TenantDomainFilter.TENANT_ATTRIBUTE)}
 * or {@code TenantDomainFilter.getCurrentTenant(request)}
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class TenantDomainFilter extends OncePerRequestFilter {

    public static final String TENANT_ATTRIBUTE = "tenantDomain";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String tenant = extractTenantFromHostname(request);
        if (tenant == null) {
            tenant = extractTenantFromHeader(request);
        }
        if (tenant != null) {
            request.setAttribute(TENANT_ATTRIBUTE, tenant);
            MDC.put("tenantDomain", tenant);
            log.trace("Verifier: Resolved tenant '{}' from request hostname", tenant);
        }
        try {
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove("tenantDomain");
        }
    }

    private String extractTenantFromHostname(HttpServletRequest request) {
        String hostname = request.getServerName();
        if (hostname == null || hostname.isBlank()) {
            return null;
        }

        // Atlassian-style: tenant is the first segment
        // kpmg.eudistack.net → kpmg, dome.127.0.0.1.nip.io → dome
        int dotIndex = hostname.indexOf('.');
        if (dotIndex <= 0) {
            return null;
        }

        String tenant = hostname.substring(0, dotIndex);
        if (!tenant.matches("^[a-zA-Z0-9_-]+$")) {
            log.warn("Verifier: Invalid tenant identifier from hostname: {}", tenant);
            return null;
        }
        return tenant.toLowerCase();
    }

    private String extractTenantFromHeader(HttpServletRequest request) {
        String header = request.getHeader(X_TENANT_HEADER);
        if (header == null || header.isBlank()) {
            return null;
        }
        if (!header.matches("^[a-zA-Z0-9_-]+$")) {
            log.warn("Verifier: Invalid tenant identifier from X-Tenant header: {}", header);
            return null;
        }
        return header.toLowerCase();
    }

    /**
     * Convenience method to read the tenant from the current request.
     */
    public static String getCurrentTenant(HttpServletRequest request) {
        Object tenant = request.getAttribute(TENANT_ATTRIBUTE);
        return tenant instanceof String s ? s : null;
    }
}
