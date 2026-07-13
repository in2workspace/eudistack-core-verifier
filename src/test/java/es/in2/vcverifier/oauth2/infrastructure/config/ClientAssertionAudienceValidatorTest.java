package es.in2.vcverifier.oauth2.infrastructure.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientAssertionAudienceValidatorTest {

    private static final String CLEAN_ISSUER = "https://verifier.dome-marketplace-lcl.org";
    private static final String CONTEXT_PATH = "/verifier";
    private static final String CONTEXT_ISSUER = CLEAN_ISSUER + CONTEXT_PATH;
    private static final String TOKEN_ENDPOINT = "/oidc/token";

    private final ClientAssertionAudienceValidator validator = new ClientAssertionAudienceValidator();

    @BeforeEach
    void setUp() {
        // Simulate the running app: issuer derived by Spring includes the /verifier context-path,
        // and the servlet request carries that same context-path.
        AuthorizationServerSettings settings = AuthorizationServerSettings.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .build();
        AuthorizationServerContextHolder.setContext(new AuthorizationServerContext() {
            @Override
            public String getIssuer() {
                return CONTEXT_ISSUER;
            }

            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return settings;
            }
        });

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath(CONTEXT_PATH);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @AfterEach
    void tearDown() {
        AuthorizationServerContextHolder.resetContext();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void validate_audienceWithContextPath_isAccepted() {
        assertTrue(validate(CONTEXT_ISSUER).getErrors().isEmpty());
    }

    @Test
    void validate_audienceWithoutContextPath_legacyClient_isAccepted() {
        // The failing production case: legacy client points at the clean URL (no /verifier).
        assertTrue(validate(CLEAN_ISSUER).getErrors().isEmpty());
    }

    @Test
    void validate_audienceCleanTokenEndpoint_isAccepted() {
        assertTrue(validate(CLEAN_ISSUER + TOKEN_ENDPOINT).getErrors().isEmpty());
    }

    @Test
    void validate_audienceContextPathTokenEndpoint_isAccepted() {
        assertTrue(validate(CONTEXT_ISSUER + TOKEN_ENDPOINT).getErrors().isEmpty());
    }

    @Test
    void validate_audienceWrongHost_isRejected() {
        assertFalse(validate("https://evil.example.org").getErrors().isEmpty());
    }

    @Test
    void validate_audienceEmpty_isRejected() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("client")
                .build();
        assertFalse(validator.validate(jwt).getErrors().isEmpty());
    }

    @Test
    void validate_noAuthorizationServerContext_isRejected() {
        AuthorizationServerContextHolder.resetContext();
        assertFalse(validate(CLEAN_ISSUER).getErrors().isEmpty());
    }

    private OAuth2TokenValidatorResult validate(String audience) {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("client")
                .audience(List.of(audience))
                .issuedAt(Instant.now())
                .build();
        return validator.validate(jwt);
    }
}
