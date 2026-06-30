package es.in2.vcverifier.oauth2.infrastructure.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final PublicCorsConfig publicCorsConfig;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(publicCorsConfig.publicCorsConfigurationSource()))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/health").permitAll()
                        .requestMatchers("/prometheus").permitAll()
                        .requestMatchers("/oid4vp/auth-request/*").permitAll()
                        .requestMatchers("/oid4vp/auth-response").permitAll()
                        .requestMatchers("/oidc/did/*").permitAll()
                        .requestMatchers("/api/login/**").permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf
                        // Apply CSRF only to the specified routes
                        .requireCsrfProtectionMatcher(new CsrfProtectionMatcher()) //NOSONAR: CORS Config is intentional to allow access to all Wallets
                )
                .exceptionHandling(ex -> ex
                        // ES-03: unauthenticated requests return 401 (not 403)
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                )
                .formLogin(AbstractHttpConfigurer::disable);
        return http.build();
    }


    private static class CsrfProtectionMatcher implements RequestMatcher {
        private final AntPathRequestMatcher[] requestMatchers = {
                new AntPathRequestMatcher("/health"),
                new AntPathRequestMatcher("/prometheus"),
                new AntPathRequestMatcher("/oid4vp/auth-request/**"),
                new AntPathRequestMatcher("/oid4vp/auth-response"),
                new AntPathRequestMatcher("/oidc/did/**"),
                new AntPathRequestMatcher("/api/login/**")
        };

        @Override
        public boolean matches(HttpServletRequest request) {
            // Safe HTTP methods never need CSRF protection (RFC 7231)
            String method = request.getMethod();
            if ("GET".equals(method) || "HEAD".equals(method)
                    || "TRACE".equals(method) || "OPTIONS".equals(method)) {
                return false;
            }
            // Disable CSRF for the specified routes
            for (AntPathRequestMatcher matcher : requestMatchers) {
                if (matcher.matches(request)) {
                    return false;
                }
            }
            // Apply CSRF to all other routes
            return true;
        }
    }

}
