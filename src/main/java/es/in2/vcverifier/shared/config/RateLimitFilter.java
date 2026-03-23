package es.in2.vcverifier.shared.config;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SEC-S4: Per-IP rate limiting filter.
 * Applies to all requests. Auth-sensitive endpoints have stricter limits.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RateLimitFilter implements Filter {

    private static final int GENERAL_LIMIT_PER_MINUTE = 120;
    private static final int AUTH_LIMIT_PER_MINUTE = 30;

    private final Cache<String, AtomicInteger> generalBuckets = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.MINUTES)
            .maximumSize(50_000)
            .build();

    private final Cache<String, AtomicInteger> authBuckets = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.MINUTES)
            .maximumSize(50_000)
            .build();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest httpRequest) ||
                !(response instanceof HttpServletResponse httpResponse)) {
            chain.doFilter(request, response);
            return;
        }

        String clientIp = resolveClientIp(httpRequest);
        String path = httpRequest.getRequestURI();

        // Stricter limit for auth-sensitive endpoints
        if (isAuthEndpoint(path)) {
            if (isRateLimited(clientIp, authBuckets, AUTH_LIMIT_PER_MINUTE)) {
                log.warn("Rate limit exceeded for auth endpoint: ip={}, path={}", clientIp, path);
                httpResponse.setStatus(429);
                httpResponse.setHeader("Retry-After", "60");
                return;
            }
        }

        // General limit for all endpoints
        if (isRateLimited(clientIp, generalBuckets, GENERAL_LIMIT_PER_MINUTE)) {
            log.warn("Rate limit exceeded: ip={}, path={}", clientIp, path);
            httpResponse.setStatus(429);
            httpResponse.setHeader("Retry-After", "60");
            return;
        }

        chain.doFilter(request, response);
    }

    private boolean isAuthEndpoint(String path) {
        return path.startsWith("/oidc/token")
                || path.startsWith("/oid4vp/auth-response")
                || path.startsWith("/oidc/authorize");
    }

    private boolean isRateLimited(String clientIp, Cache<String, AtomicInteger> buckets, int limit) {
        try {
            AtomicInteger counter = buckets.get(clientIp, () -> new AtomicInteger(0));
            return counter.incrementAndGet() > limit;
        } catch (ExecutionException e) {
            return false;
        }
    }

    private String resolveClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            // Take only the first (client) IP to prevent spoofing via appended headers
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
