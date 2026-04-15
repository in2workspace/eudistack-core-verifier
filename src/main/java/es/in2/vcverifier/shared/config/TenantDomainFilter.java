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

/**
 * Extracts the tenant identifier from the request hostname and stores it
 * as a request attribute. Pattern: {service}.{tenant}.domain
 *
 * <p>After {@code ForwardedHeaderFilter} has processed X-Forwarded-Host,
 * {@code request.getServerName()} returns the original public hostname.
 * The tenant is the second segment:
 * <ul>
 *   <li>{@code verifier.kpmg.127.0.0.1.nip.io} → {@code kpmg}</li>
 *   <li>{@code verifier.dome.eudistack.net} → {@code dome}</li>
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
        if (tenant != null) {
            request.setAttribute(TENANT_ATTRIBUTE, tenant);
            log.trace("Verifier: Resolved tenant '{}' from request hostname", tenant);
        }
        filterChain.doFilter(request, response);
    }

    private String extractTenantFromHostname(HttpServletRequest request) {
        String hostname = request.getServerName();
        if (hostname == null || hostname.isBlank()) {
            return null;
        }

        String[] segments = hostname.split("\\.");
        // Pattern: {service}.{tenant}.{rest...}
        if (segments.length < 3) {
            return null;
        }

        String tenant = segments[1];
        if (!tenant.matches("^[a-zA-Z0-9_-]+$")) {
            log.warn("Verifier: Invalid tenant identifier from hostname: {}", tenant);
            return null;
        }
        return tenant.toLowerCase();
    }

    /**
     * Convenience method to read the tenant from the current request.
     */
    public static String getCurrentTenant(HttpServletRequest request) {
        Object tenant = request.getAttribute(TENANT_ATTRIBUTE);
        return tenant instanceof String s ? s : null;
    }
}
