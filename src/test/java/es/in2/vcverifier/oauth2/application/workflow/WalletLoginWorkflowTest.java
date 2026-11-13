package es.in2.vcverifier.oauth2.application.workflow;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.verifier.application.workflow.AuthorizationRequestBuildWorkflow;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static es.in2.vcverifier.shared.domain.util.Constants.VP_NONCE;
import static es.in2.vcverifier.shared.domain.util.Constants.WALLET_AUTH_REQUEST;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class WalletLoginWorkflowTest {

    private static final String AUTH_REQUEST = "openid4vp://?client_id=verifier&request_uri=https://verifier/oid4vp/r/abc";

    @Mock
    private AuthorizationRequestBuildWorkflow authorizationRequestBuildWorkflow;

    @Mock
    private BackendConfig backendConfig;

    @InjectMocks
    private WalletLoginWorkflow workflow;

    @Test
    void start_signsTheWalletRequestAndStartsTheLoginTime() {
        RegisteredClient client = RegisteredClient.withId("c1")
                .clientId("c1")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://portal.example.com/callback")
                .build();
        when(authorizationRequestBuildWorkflow.buildAuthorizationRequest(client, "openid doctorid", "s-1", "issuer_access"))
                .thenReturn(new AuthorizationRequestBuildWorkflow.Result("jwt", AUTH_REQUEST, "abc", "vp-nonce"));
        when(backendConfig.getLoginTimeoutSeconds()).thenReturn(120L);

        WalletLoginWorkflow.WalletLogin walletLogin = workflow.start(client, "openid doctorid", "s-1", "issuer_access");

        assertThat(walletLogin.authRequest()).isEqualTo(AUTH_REQUEST);
        assertThat(walletLogin.vpNonce()).isEqualTo("vp-nonce");
        assertThat(walletLogin.expiresAt())
                .isBetween(Instant.now().plusSeconds(119).getEpochSecond(), Instant.now().plusSeconds(120).getEpochSecond());
    }

    @Test
    void addTo_putsTheWalletRequestItsNonceAndTheExpirationInTheLogin() {
        Map<String, Object> loginParameters = new HashMap<>(Map.of(EXPIRATION, 1L, "other", "kept"));

        new WalletLoginWorkflow.WalletLogin(AUTH_REQUEST, "vp-nonce", 42L).addTo(loginParameters);

        assertThat(loginParameters)
                .containsEntry(WALLET_AUTH_REQUEST, AUTH_REQUEST)
                .containsEntry(VP_NONCE, "vp-nonce")
                .containsEntry(EXPIRATION, 42L)
                .containsEntry("other", "kept");
    }
}
