package es.in2.vcverifier.oauth2.infrastructure.filter;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Lets a client_credentials request with a client_assertion through Spring's client
 * authentication step when the client_id is NOT in the registered client repository.
 *
 * Spring's built-in converters (client_secret_basic/post, private_key_jwt, PKCE-public,
 * mTLS) all require the client to already exist in {@link RegisteredClientRepository},
 * so an unregistered machine client is rejected with a bare 401 before ever reaching
 * {@link CustomTokenRequestConverter} / {@link CustomAuthenticationProvider} — the classes
 * that actually validate the embedded verifiable presentation and derive the client's
 * real identity and tenant from it.
 *
 * This converter performs NO validation of its own: it only recognizes the request shape
 * and defers entirely to the downstream grant-processing pipeline, which is where the
 * real security checks (VP signature, issuer trust, revocation, tenant match) live.
 */
@RequiredArgsConstructor
public class UnregisteredM2MClientAuthenticationConverter implements AuthenticationConverter {

    public static final ClientAuthenticationMethod UNREGISTERED_VC_METHOD =
            new ClientAuthenticationMethod("urn:eudistack:oauth:client-authentication-type:unregistered-vc");

    private final RegisteredClientRepository registeredClientRepository;

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return null;
        }

        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(grantType)) {
            return null;
        }

        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String clientAssertion = request.getParameter(OAuth2ParameterNames.CLIENT_ASSERTION);
        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(clientAssertion)) {
            return null;
        }

        // Pre-registered clients (H2M or M2M) keep using Spring's built-in mechanisms untouched.
        if (registeredClientRepository.findByClientId(clientId) != null) {
            return null;
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        request.getParameterMap().forEach((key, values) -> {
            if (!OAuth2ParameterNames.CLIENT_ID.equals(key) && values.length > 0) {
                additionalParameters.put(key, values.length == 1 ? values[0] : values);
            }
        });

        return new OAuth2ClientAuthenticationToken(clientId, UNREGISTERED_VC_METHOD, clientAssertion,
                additionalParameters);
    }
}
