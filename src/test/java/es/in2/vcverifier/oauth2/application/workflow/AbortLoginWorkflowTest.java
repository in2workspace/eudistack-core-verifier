package es.in2.vcverifier.oauth2.application.workflow;

import es.in2.vcverifier.shared.config.CacheStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class AbortLoginWorkflowTest {

    private CacheStore<OAuth2AuthorizationRequest> cache;
    private AbortLoginWorkflow workflow;

    @BeforeEach
    void setUp() {
        cache = new CacheStore<>(10, TimeUnit.MINUTES);
        workflow = new AbortLoginWorkflow(cache);
    }

    private void cachePendingLogin(String state, String redirectUri) {
        cache.add(state, OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://verifier.example.com")
                .clientId("marketplace-client")
                .redirectUri(redirectUri)
                .state(state)
                .build());
    }

    @Test
    void abort_pendingLogin_returnsRelyingPartyRedirectWithAccessDenied() {
        cachePendingLogin("state-1", "https://marketplace.example.com/callback");

        Optional<String> result = workflow.abort("state-1");

        assertThat(result).contains(
                "https://marketplace.example.com/callback?error=access_denied&error_description=login_timeout&state=state-1");
    }

    @Test
    void abort_redirectUriWithQuery_appendsParamsWithAmpersand() {
        cachePendingLogin("state-1", "https://rp.example.com/cb?tenant=dome");

        Optional<String> result = workflow.abort("state-1");

        assertThat(result).contains(
                "https://rp.example.com/cb?tenant=dome&error=access_denied&error_description=login_timeout&state=state-1");
    }

    @Test
    void abort_stateWithReservedCharacters_isUrlEncoded() {
        cachePendingLogin("a b&c=d", "https://rp.example.com/cb");

        Optional<String> result = workflow.abort("a b&c=d");

        assertThat(result).hasValueSatisfying(url -> assertThat(url).endsWith("&state=a+b%26c%3Dd"));
    }

    @Test
    void abort_removesPendingLogin_soItCannotBeCompletedOrAbortedAgain() {
        cachePendingLogin("state-1", "https://rp.example.com/cb");

        workflow.abort("state-1");

        assertThat(cache.getIfPresent("state-1")).isNull();
        assertThat(workflow.abort("state-1")).isEmpty();
    }

    @Test
    void abort_unknownState_returnsEmpty() {
        assertThat(workflow.abort("unknown")).isEmpty();
    }
}
