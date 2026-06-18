package es.in2.vcverifier.oauth2.infrastructure.filter;

import es.in2.vcverifier.shared.config.BackendConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Overrides the issuer in {@link AuthorizationServerContextHolder} with the URL from
 * {@link BackendConfig#getUrl()}, which already handles canonical vs. non-canonical routing:
 * <ul>
 *   <li>Canonical (no {@code X-Tenant} header): returns {@code base + contextPath}
 *       → issuer includes {@code /verifier}</li>
 *   <li>Non-canonical ({@code X-Tenant} header set by proxy): returns {@code base} only
 *       → issuer without {@code /verifier}, so discovery URLs match the external URL</li>
 * </ul>
 *
 * <p>This filter must run <em>after</em> Spring AS's {@code AuthorizationServerContextFilter}
 * (which sets the initial context) and <em>before</em> any endpoint filter that reads
 * {@link AuthorizationServerContextHolder#getContext()} to build response URLs.
 * It is registered via
 * {@code http.addFilterBefore(this, OAuth2AuthorizationEndpointFilter.class)}.
 */
@RequiredArgsConstructor
public class IssuerOverrideFilter extends OncePerRequestFilter {

    private final BackendConfig backendConfig;
    private final AuthorizationServerSettings authorizationServerSettings;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String issuer = backendConfig.getUrl();
        AuthorizationServerContextHolder.setContext(new OverriddenAuthorizationServerContext(issuer, authorizationServerSettings));
        try {
            chain.doFilter(request, response);
        } finally {
            AuthorizationServerContextHolder.resetContext();
        }
    }

    private record OverriddenAuthorizationServerContext(
            String issuer,
            AuthorizationServerSettings authorizationServerSettings
    ) implements AuthorizationServerContext {

        @Override
        public String getIssuer() {
            return issuer;
        }

        @Override
        public AuthorizationServerSettings getAuthorizationServerSettings() {
            return authorizationServerSettings;
        }
    }
}
