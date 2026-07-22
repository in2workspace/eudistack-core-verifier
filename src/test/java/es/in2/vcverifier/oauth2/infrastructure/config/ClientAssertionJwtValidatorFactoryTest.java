package es.in2.vcverifier.oauth2.infrastructure.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientAssertionJwtValidatorFactoryTest {

    private static final String ISSUER = "https://verifier.dome-marketplace-lcl.org/verifier";
    private static final String CLIENT_ID = "did:key:zClient";

    private final ClientAssertionJwtValidatorFactory factory = new ClientAssertionJwtValidatorFactory();
    private OAuth2TokenValidator<Jwt> validator;

    @BeforeEach
    void setUp() {
        AuthorizationServerSettings settings = AuthorizationServerSettings.builder()
                .tokenEndpoint("/oidc/token")
                .build();
        AuthorizationServerContextHolder.setContext(new AuthorizationServerContext() {
            @Override
            public String getIssuer() {
                return ISSUER;
            }

            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return settings;
            }
        });
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("/verifier");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
        this.validator = factory.apply(registeredClient);
    }

    @AfterEach
    void tearDown() {
        AuthorizationServerContextHolder.resetContext();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void apply_validAssertion_passes() {
        assertTrue(validator.validate(assertion(CLIENT_ID, CLIENT_ID, Instant.now().plusSeconds(300))).getErrors().isEmpty());
    }

    @Test
    void apply_issuerNotClientId_fails() {
        assertFalse(validator.validate(assertion("someone-else", CLIENT_ID, Instant.now().plusSeconds(300))).getErrors().isEmpty());
    }

    @Test
    void apply_subjectNotClientId_fails() {
        assertFalse(validator.validate(assertion(CLIENT_ID, "someone-else", Instant.now().plusSeconds(300))).getErrors().isEmpty());
    }

    @Test
    void apply_expired_fails() {
        assertFalse(validator.validate(assertion(CLIENT_ID, CLIENT_ID, Instant.now().minusSeconds(300))).getErrors().isEmpty());
    }

    private Jwt assertion(String iss, String sub, Instant exp) {
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claim("iss", iss)
                .subject(sub)
                .audience(List.of(ISSUER))
                .issuedAt(exp.minusSeconds(60))
                .expiresAt(exp)
                .build();
    }
}
