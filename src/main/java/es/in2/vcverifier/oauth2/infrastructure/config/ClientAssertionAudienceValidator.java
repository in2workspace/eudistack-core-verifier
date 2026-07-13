package es.in2.vcverifier.oauth2.infrastructure.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Validates the {@code aud} claim of a {@code client_assertion} (private_key_jwt client
 * authentication, RFC 7523) for the OAuth2 authorization_code / refresh_token flows.
 *
 * <p>Spring's default {@code JwtClientAssertionDecoderFactory} only accepts audiences derived
 * from {@link AuthorizationServerContext#getIssuer()}, which — because the app runs with
 * {@code server.servlet.context-path=/verifier} and no explicitly configured issuer — always
 * includes the internal {@code /verifier} prefix. Legacy clients, however, point to the clean
 * public URL (without {@code /verifier}) and therefore sign the assertion with a matching
 * {@code aud}. That mismatch causes {@code invalid_client: The aud claim is not valid}.
 *
 * <p>This validator accepts the audience in BOTH forms — with and without the servlet
 * context-path — so legacy clients (clean URL) and context-path-aware clients both work. The
 * context-path is read dynamically from the request, so nothing is hard-coded to {@code /verifier},
 * and derivation from the request host keeps it multi-tenant aware.
 */
@Slf4j
public class ClientAssertionAudienceValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error INVALID_AUD = new OAuth2Error(
            OAuth2ErrorCodes.INVALID_CLIENT,
            "The aud claim is not valid",
            "https://datatracker.ietf.org/doc/html/rfc7523#section-3");

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<String> receivedAudiences = jwt.getAudience();
        Set<String> expectedAudiences = buildExpectedAudiences();

        boolean matches = receivedAudiences != null && receivedAudiences.stream().anyMatch(expectedAudiences::contains);

        if (matches) {
            log.debug("client_assertion aud validation OK. received={}, expected={}", receivedAudiences, expectedAudiences);
            return OAuth2TokenValidatorResult.success();
        }

        log.warn("client_assertion aud validation FAILED. received={}, expected={}", receivedAudiences, expectedAudiences);
        return OAuth2TokenValidatorResult.failure(INVALID_AUD);
    }

    /**
     * Builds the set of accepted audiences from the request-derived issuer, in both the
     * context-path form (e.g. {@code https://host/verifier}) and the clean form
     * (e.g. {@code https://host}), each with its {@code token} endpoint variant.
     */
    private Set<String> buildExpectedAudiences() {
        Set<String> audiences = new LinkedHashSet<>();

        AuthorizationServerContext context = AuthorizationServerContextHolder.getContext();
        if (context == null) {
            return audiences;
        }
        String issuer = context.getIssuer();
        if (issuer == null || issuer.isBlank()) {
            return audiences;
        }
        String tokenEndpoint = context.getAuthorizationServerSettings().getTokenEndpoint();

        // Form 1: issuer as Spring derives it (includes the servlet context-path, e.g. /verifier)
        addAudienceVariants(audiences, issuer, tokenEndpoint);

        // Form 2: issuer with the servlet context-path stripped (the clean public URL legacy clients use)
        String contextPath = currentContextPath();
        if (!contextPath.isEmpty() && issuer.endsWith(contextPath)) {
            String cleanIssuer = issuer.substring(0, issuer.length() - contextPath.length());
            addAudienceVariants(audiences, cleanIssuer, tokenEndpoint);
        }

        return audiences;
    }

    private void addAudienceVariants(Set<String> audiences, String base, String tokenEndpoint) {
        audiences.add(base);
        if (tokenEndpoint != null && !tokenEndpoint.isBlank()) {
            audiences.add(base + tokenEndpoint);
        }
    }

    private String currentContextPath() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
            HttpServletRequest request = attrs.getRequest();
            String contextPath = request.getContextPath();
            if (contextPath != null) {
                return contextPath;
            }
        }
        return "";
    }
}
