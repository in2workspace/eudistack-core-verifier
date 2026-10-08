package es.in2.vcverifier.oauth2.application.workflow;

import es.in2.vcverifier.shared.config.CacheStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.spy;

class AbortLoginWorkflowTest {

    private CacheStore<OAuth2AuthorizationRequest> cache;
    private AbortLoginWorkflow workflow;

    @BeforeEach
    void setUp() {
        cache = new CacheStore<>(10, TimeUnit.MINUTES);
        workflow = new AbortLoginWorkflow(cache);
    }

    private void cacheExpiredLogin(String state, String redirectUri) {
        cacheLogin(state, redirectUri, Map.of(EXPIRATION, Instant.now().minusSeconds(1).getEpochSecond()));
    }

    private void cacheLogin(String state, String redirectUri, Map<String, Object> additionalParameters) {
        cache.add(state, OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://verifier.example.com")
                .clientId("marketplace-client")
                .redirectUri(redirectUri)
                .state(state)
                .additionalParameters(additionalParameters)
                .build());
    }

    @Test
    void abort_loginNotExpiredYet_isRejectedAndLeftPending() {
        cacheLogin("state-1", "https://rp.example.com/cb",
                Map.of(EXPIRATION, Instant.now().plusSeconds(60).getEpochSecond()));

        assertThat(workflow.abort("state-1")).isEmpty();
        assertThat(cache.getIfPresent("state-1")).isNotNull();
    }

    @Test
    void abort_withinTheMarginBeforeExpiration_isAccepted() {
        cacheLogin("state-1", "https://rp.example.com/cb",
                Map.of(EXPIRATION, Instant.now().plusSeconds(2).getEpochSecond()));

        assertThat(workflow.abort("state-1")).isPresent();
    }

    @Test
    void abort_loginWithoutExpiration_isRejected() {
        cacheLogin("state-1", "https://rp.example.com/cb", Map.of());

        assertThat(workflow.abort("state-1")).isEmpty();
        assertThat(cache.getIfPresent("state-1")).isNotNull();
    }

    @Test
    void abort_pendingLogin_returnsRelyingPartyRedirectWithAccessDenied() {
        cacheExpiredLogin("state-1", "https://marketplace.example.com/callback");

        Optional<String> result = workflow.abort("state-1");

        assertThat(result).contains(
                "https://marketplace.example.com/callback?error=access_denied&error_description=login_timeout&state=state-1");
    }

    @Test
    void abort_redirectUriWithQuery_appendsParamsWithAmpersand() {
        cacheExpiredLogin("state-1", "https://rp.example.com/cb?tenant=dome");

        Optional<String> result = workflow.abort("state-1");

        assertThat(result).contains(
                "https://rp.example.com/cb?tenant=dome&error=access_denied&error_description=login_timeout&state=state-1");
    }

    @Test
    void abort_stateWithReservedCharacters_isUrlEncoded() {
        cacheExpiredLogin("a b&c=d", "https://rp.example.com/cb");

        Optional<String> result = workflow.abort("a b&c=d");

        assertThat(result).hasValueSatisfying(url -> assertThat(url).endsWith("&state=a+b%26c%3Dd"));
    }

    @Test
    void abort_removesPendingLogin_soItCannotBeCompletedOrAbortedAgain() {
        cacheExpiredLogin("state-1", "https://rp.example.com/cb");

        workflow.abort("state-1");

        assertThat(cache.getIfPresent("state-1")).isNull();
        assertThat(workflow.abort("state-1")).isEmpty();
    }

    @Test
    void abort_unknownState_returnsEmpty() {
        assertThat(workflow.abort("unknown")).isEmpty();
    }

    @Test
    void abort_afterPresentationTookTheLogin_returnsEmpty() {
        cacheExpiredLogin("state-1", "https://rp.example.com/cb");
        cache.remove("state-1"); // the wallet presentation is completing this login

        assertThat(workflow.abort("state-1")).isEmpty();
    }

    @Test
    void abort_loginReplacedByASameBrowserRetryAfterTheCheck_leavesTheFreshLogin() {
        cacheExpiredLogin("state-1", "https://rp.example.com/cb");
        OAuth2AuthorizationRequest checked = cache.getIfPresent("state-1");
        // A same-browser /authorize retry lands between abort's expiry check and its removal.
        CacheStore<OAuth2AuthorizationRequest> racingCache = spy(cache);
        doAnswer(invocation -> {
            cacheLogin("state-1", "https://rp.example.com/cb",
                    Map.of(EXPIRATION, Instant.now().plusSeconds(120).getEpochSecond()));
            return checked;
        }).when(racingCache).getIfPresent("state-1");

        assertThat(new AbortLoginWorkflow(racingCache).abort("state-1")).isEmpty();
        assertThat(cache.getIfPresent("state-1")).isNotNull().isNotSameAs(checked);
    }
}
