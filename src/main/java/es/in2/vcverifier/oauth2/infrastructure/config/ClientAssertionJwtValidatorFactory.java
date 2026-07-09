package es.in2.vcverifier.oauth2.infrastructure.config;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.function.Function;

/**
 * Produces the {@link OAuth2TokenValidator} used to validate a {@code client_assertion} JWT
 * during OAuth2 client authentication (private_key_jwt, RFC 7523).
 *
 * <p>Mirrors Spring's {@code JwtClientAssertionDecoderFactory#DEFAULT_JWT_VALIDATOR_FACTORY}
 * (validating {@code iss}, {@code sub}, {@code exp}/{@code nbf} exactly as the default does),
 * replacing ONLY the {@code aud} validation with {@link ClientAssertionAudienceValidator}, which
 * accepts the audience with and without the servlet context-path so legacy clients pointing at
 * the clean public URL keep working.
 *
 * @see ClientAssertionAudienceValidator
 */
public class ClientAssertionJwtValidatorFactory implements Function<RegisteredClient, OAuth2TokenValidator<Jwt>> {

    @Override
    public OAuth2TokenValidator<Jwt> apply(RegisteredClient registeredClient) {
        String clientId = registeredClient.getClientId();
        return new DelegatingOAuth2TokenValidator<>(
                new JwtClaimValidator<String>(JwtClaimNames.ISS, clientId::equals),
                new JwtClaimValidator<String>(JwtClaimNames.SUB, clientId::equals),
                new ClientAssertionAudienceValidator(),
                new JwtTimestampValidator());
    }
}
