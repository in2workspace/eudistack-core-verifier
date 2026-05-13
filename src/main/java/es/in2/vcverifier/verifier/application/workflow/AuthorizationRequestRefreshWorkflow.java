package es.in2.vcverifier.verifier.application.workflow;

import es.in2.vcverifier.shared.config.CacheStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationRequestRefreshWorkflow {

    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final RegisteredClientRepository registeredClientRepository;
    private final AuthorizationRequestBuildWorkflow authorizationRequestBuildWorkflow;

    public record Result(String openid4vpUrl) {}

    public Result refresh(String state) {
        OAuth2AuthorizationRequest authorizationRequest = cacheStoreForOAuth2AuthorizationRequest.get(state);

        String clientId = authorizationRequest.getClientId();
        String scope = String.join(" ", authorizationRequest.getScopes());

        var registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            log.warn("Refresh QR: registered client not found for clientId={}", clientId);
            throw new NoSuchElementException("Registered client not found: " + clientId);
        }

        AuthorizationRequestBuildWorkflow.Result result =
                authorizationRequestBuildWorkflow.buildAuthorizationRequest(registeredClient, scope, state);

        log.info("QR refreshed for state={}", state.substring(0, Math.min(8, state.length())));
        return new Result(result.openid4vpUrl());
    }
}
