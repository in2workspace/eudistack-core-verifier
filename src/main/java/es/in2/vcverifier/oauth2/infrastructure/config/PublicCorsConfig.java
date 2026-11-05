package es.in2.vcverifier.oauth2.infrastructure.config;

import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.config.properties.CertificateLoginProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class PublicCorsConfig {

    private static final List<String> PUBLIC_ALLOWED_HEADERS =
            List.of(HttpHeaders.CONTENT_TYPE, HttpHeaders.AUTHORIZATION, HttpHeaders.CACHE_CONTROL);

    private final CertificateLoginProperties certificateLoginProperties;

    @Bean
    public CorsConfigurationSource publicCorsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Configure public endpoints
        CorsConfiguration publicConfig = new CorsConfiguration();
        publicConfig.setAllowedOriginPatterns(List.of("*")); //NOSONAR: CORS Config is intentional to allow access to all Wallets
        publicConfig.setAllowedMethods(List.of(HttpMethod.GET.name(), HttpMethod.POST.name()));
        publicConfig.setAllowedHeaders(PUBLIC_ALLOWED_HEADERS);
        publicConfig.setAllowCredentials(false);
        source.registerCorsConfiguration("/health", publicConfig);
        source.registerCorsConfiguration("/.well-known/**", publicConfig);
        source.registerCorsConfiguration("/oidc/**", publicConfig);
        source.registerCorsConfiguration("/oid4vp/r/**", publicConfig);
        source.registerCorsConfiguration("/oid4vp/auth-request/**", publicConfig);
        source.registerCorsConfiguration("/api/login/**", publicConfig);

        // SsoSessionAuthenticationSuccessHandler sets the SSO session cookie as a Set-Cookie
        // header on the response to this endpoint, which the wallet calls cross-origin
        // (wallet.<tenant>.* -> verifier.<tenant>.*, or verifier-<tenant>.* locally). A browser
        // only stores Set-Cookie from a cross-origin XHR/fetch response when BOTH sides opt into
        // credentials: the client sends withCredentials/credentials:'include' (see
        // WalletService.postOid4vpAuthorizationResponse in eudistack-core-wallet-pwa), AND the
        // server answers with Access-Control-Allow-Credentials: true. With the shared
        // allowCredentials(false) publicConfig above, the cookie was silently discarded on every
        // establishment — every later SSO reuse attempt then saw zero cookies, unconditionally,
        // regardless of any other fix (EUDISTACK-548 investigation). Kept as its own
        // CorsConfiguration (not just flipping the flag on publicConfig) so the other, genuinely
        // cookie-free public endpoints above don't unnecessarily widen their CORS surface.
        //
        // Wallets aren't pre-registered clients with a known origin list, so this must still
        // accept any origin — setAllowedOriginPatterns("*") (pattern-based) is what makes that
        // combinable with allowCredentials(true) at all: Spring reflects the actual request's
        // Origin header back per-request instead of emitting a literal "*", which the CORS spec
        // forbids pairing with credentials (setAllowedOrigins("*") would not work here).
        CorsConfiguration authResponseConfig = new CorsConfiguration();
        authResponseConfig.setAllowedOriginPatterns(List.of("*")); //NOSONAR: any wallet must be able to call this, see comment above
        authResponseConfig.setAllowedMethods(List.of(HttpMethod.POST.name()));
        authResponseConfig.setAllowedHeaders(PUBLIC_ALLOWED_HEADERS);
        authResponseConfig.setAllowCredentials(true);
        source.registerCorsConfiguration("/oid4vp/auth-response", authResponseConfig);
        return request -> isCertificateLogin(request)
                ? certificateLoginCorsConfiguration(request)
                : source.getCorsConfiguration(request);
    }

    private boolean isCertificateLogin(HttpServletRequest request) {
        return request.getLocalPort() == certificateLoginProperties.port();
    }

    private CorsConfiguration certificateLoginCorsConfiguration(HttpServletRequest request) {
        CorsConfiguration certificateConfig = new CorsConfiguration();
        String tenant = TenantDomainFilter.getCurrentTenant(request);
        CertificateLoginProperties.Tenant entry = tenant == null ? null : certificateLoginProperties.tenants().get(tenant);
        if (entry != null) {
            certificateConfig.setAllowedOrigins(List.of(entry.loginOrigin()));
        }
        certificateConfig.setAllowedMethods(List.of(HttpMethod.POST.name()));
        certificateConfig.setAllowedHeaders(List.of(HttpHeaders.CONTENT_TYPE));
        certificateConfig.setAllowCredentials(true);
        return certificateConfig;
    }

}
