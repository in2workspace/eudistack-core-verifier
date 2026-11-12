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
 * Resolves the tenant identifier from the request and stores it as a request
 * attribute and in the MDC.
 *
 * <p>Resolution order:
 * <ol>
 *   <li>Value of the tenant header, validated and normalized to lowercase.</li>
 *   <li>First hostname segment, validated and normalized to lowercase.</li>
 * </ol>
 *
 * <p>Atlassian-style hostname resolution: the tenant is the first hostname segment.
 * Examples:
 * <ul>
 *   <li>{@code kpmg.eudistack.net} → {@code kpmg}</li>
 *   <li>{@code dome.127.0.0.1.nip.io} → {@code dome}</li>
 * </ul>
 *
 * <p>This filter expects forwarded headers to have already been processed
 * so {@code request.getServerName()} contains the public hostname.
 *
 * <p>Read the tenant elsewhere via:
 * {@code request.getAttribute(TenantDomainFilter.TENANT_ATTRIBUTE)}
 * or {@code TenantDomainFilter.getCurrentTenant(request)}.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class TenantDomainFilter extends OncePerRequestFilter {

    public static final String TENANT_ATTRIBUTE = "tenantDomain";

    private static final String MDC_TENANT_DOMAIN = "tenantDomain";
    private static final String TENANT_PATTERN = "^[a-zA-Z0-9_-]+$";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String tenant = extractTenantFromHeader(request);
        if (tenant == null) {
            tenant = extractTenantFromHostname(request);
        }

        if (tenant != null) {
            request.setAttribute(TENANT_ATTRIBUTE, tenant);
            MDC.put(MDC_TENANT_DOMAIN, tenant);
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_TENANT_DOMAIN);
        }
    }

    private String extractTenantFromHeader(HttpServletRequest request) {
        String header = request.getHeader(X_TENANT_HEADER);
        if (header == null || header.isBlank()) {
            return null;
        }

        String tenant = validateTenant(header.trim(), X_TENANT_HEADER + " header");
        if (tenant != null) {
            log.debug("Verifier: Resolved tenant '{}' from {} header", tenant, X_TENANT_HEADER);
        }
        return tenant;
    }

    private String extractTenantFromHostname(HttpServletRequest request) {
        String hostname = request.getServerName();
        if (hostname == null || hostname.isBlank()) {
            return null;
        }

        int dotIndex = hostname.indexOf('.');
        if (dotIndex <= 0) {
            return null;
        }

        String tenant = validateTenant(hostname.substring(0, dotIndex), "hostname");
        if (tenant != null) {
            log.debug("Verifier: Resolved tenant '{}' from request hostname", tenant);
        }
        return tenant;
    }

    private String validateTenant(String candidate, String source) {
        if (!candidate.matches(TENANT_PATTERN)) {
            log.warn("Verifier: Invalid tenant identifier from {}: {}", source, candidate);
            return null;
        }
        return candidate.toLowerCase();
    }

    /**
     * Convenience method to read the tenant from the current request.
     */
    public static String getCurrentTenant(HttpServletRequest request) {
        Object tenant = request.getAttribute(TENANT_ATTRIBUTE);
        return tenant instanceof String s ? s : null;
    }
}