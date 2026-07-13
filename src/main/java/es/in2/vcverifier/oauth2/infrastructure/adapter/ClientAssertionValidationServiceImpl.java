package es.in2.vcverifier.oauth2.infrastructure.adapter;

import com.nimbusds.jose.Payload;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.JtiTokenCache;
import es.in2.vcverifier.oauth2.domain.service.ClientAssertionValidationService;
import es.in2.vcverifier.shared.crypto.JWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.LinkedHashSet;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class ClientAssertionValidationServiceImpl implements ClientAssertionValidationService {

    private final BackendConfig backendConfig;
    private final JtiTokenCache jtiTokenCache;
    private final JWTService jwtService;

    @Override
    public boolean verifyClientAssertionJWTClaims(String clientId, Payload payload) {
        log.info("Starting client assertion JWT claims validation for clientId: {}", clientId);
        return validateIssuerAndSubject(clientId, payload) &&
                validateAudience(payload) &&
                validateJti(payload) &&
                validateExpiration(payload);
    }

    private boolean validateIssuerAndSubject(String clientId, Payload payload) {
        return validateIfIssuerMatchesWithClientId(clientId, payload) && validateIfSubjectMatchesWithClientId(clientId, payload);
    }

    private boolean validateIfIssuerMatchesWithClientId(String clientId, Payload payload) {
        log.debug("ClientAssertionValidationServiceImpl -- validateIfIssuerMatchesWithClientId -- Checking if 'iss' (issuer) matches clientId: {}", clientId);
        String iss = jwtService.extractClaimFromPayload(payload, "iss");
        if (!iss.equals(clientId)) {
            log.error("VpValidationServiceImpl -- validateIssuer -- The 'iss' (issuer) claim does not match the clientId.");
            return false;
        }
        log.info("ClientAssertionValidation -- 'iss' (issuer) claim matches clientId: {}", clientId);
        return true;
    }

    private boolean validateIfSubjectMatchesWithClientId(String clientId, Payload payload) {
        log.debug("ClientAssertionValidationServiceImpl -- validateIfSubjectMatchesWithClientId -- Checking if 'sub' (subject) matches clientId: {}", clientId);
        String sub = jwtService.extractClaimFromPayload(payload, "sub");
        if (!sub.equals(clientId)) {
            log.error("VpValidationServiceImpl -- validateSubject -- The 'sub' (subject) claim does not match the clientId.");
            return false;
        }
        log.info("ClientAssertionValidation -- 'sub' (subject) claim matches clientId: {}", clientId);
        return true;
    }

    private boolean validateAudience(Payload payload) {
        log.debug("ClientAssertionValidationServiceImpl -- validateAudience -- Validating 'aud' (audience) claim against expected audience");
        String aud = jwtService.extractClaimFromPayload(payload, "aud");
        Set<String> expectedAudiences = buildExpectedAudiences();

        if (aud == null || !expectedAudiences.contains(aud)) {
            log.error("ClientAssertionValidation -- validateAudience -- The 'aud' (audience) claim does not match the expected audience. received={}, expected={}", aud, expectedAudiences);
            return false;
        }
        log.info("ClientAssertionValidation -- 'aud' (audience) matches expected audience");
        return true;
    }

    /**
     * Accepts the canonical verifier URL both WITH the servlet context-path (e.g. .../verifier)
     * and WITHOUT it (the clean public URL legacy clients point at). This mirrors the tolerance
     * applied to the authorization_code path so M2M clients that never changed their URL keep
     * working after the /verifier context-path was introduced.
     */
    private Set<String> buildExpectedAudiences() {
        Set<String> audiences = new LinkedHashSet<>();
        String canonical = backendConfig.getUrl();
        if (canonical == null || canonical.isBlank()) {
            return audiences;
        }
        audiences.add(canonical);

        String contextPath = currentContextPath();
        if (!contextPath.isEmpty() && canonical.endsWith(contextPath)) {
            audiences.add(canonical.substring(0, canonical.length() - contextPath.length()));
        }
        return audiences;
    }

    private String currentContextPath() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
            String contextPath = attrs.getRequest().getContextPath();
            if (contextPath != null) {
                return contextPath;
            }
        }
        return "";
    }

    private boolean validateJti(Payload payload) {
        log.debug("ClientAssertionValidationServiceImpl -- validateJti -- Validating 'jti' (JWT ID) for replay prevention");
        String jti = jwtService.extractClaimFromPayload(payload, "jti");

        if (jtiTokenCache.isJtiPresent(jti)) {
            log.error("VpValidationServiceImpl -- validateJti -- The token with jti: {} has already been used.", jti);
            return false;
        } else {
            log.info("ClientAssertionValidation -- Adding 'jti' '{}' to cache for future replay prevention", jti);
            jtiTokenCache.addJti(jti);
        }
        return true;
    }

    private boolean validateExpiration(Payload payload) {
        log.debug("ClientAssertionValidationServiceImpl -- validateExpiration -- Validating 'exp' (expiration) claim");
        long exp = jwtService.extractExpirationFromPayload(payload);
        long currentTimeInSeconds = System.currentTimeMillis() / 1000;

        if (exp <= currentTimeInSeconds) {
            log.error("VpValidationServiceImpl -- validateExpiration -- The 'exp' (expiration) claim has expired.");
            return false;
        }
        log.info("ClientAssertionValidation -- Expiration validation successful: 'exp' (expiration) is valid");
        return true;
    }
}
