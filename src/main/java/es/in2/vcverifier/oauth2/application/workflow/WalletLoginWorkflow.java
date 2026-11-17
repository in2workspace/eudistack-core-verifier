package es.in2.vcverifier.oauth2.application.workflow;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.verifier.application.workflow.AuthorizationRequestBuildWorkflow;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;

import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static es.in2.vcverifier.shared.domain.util.Constants.VP_NONCE;
import static es.in2.vcverifier.shared.domain.util.Constants.WALLET_AUTH_REQUEST;

@Service
@RequiredArgsConstructor
public class WalletLoginWorkflow {

    private final AuthorizationRequestBuildWorkflow authorizationRequestBuildWorkflow;
    private final BackendConfig backendConfig;

    public record WalletLogin(String authRequest, String vpNonce, long expiresAt) {

        public void addTo(Map<String, Object> loginParameters) {
            loginParameters.put(WALLET_AUTH_REQUEST, authRequest);
            loginParameters.put(VP_NONCE, vpNonce);
            loginParameters.put(EXPIRATION, expiresAt);
        }
    }

    public WalletLogin start(RegisteredClient registeredClient, String scope, String state, String accessProfile) {
        AuthorizationRequestBuildWorkflow.Result walletRequest =
                authorizationRequestBuildWorkflow.buildAuthorizationRequest(registeredClient, scope, state, accessProfile);
        return new WalletLogin(walletRequest.openid4vpUrl(), walletRequest.vpNonce(),
                Instant.now().plusSeconds(backendConfig.getLoginTimeoutSeconds()).getEpochSecond());
    }
}
