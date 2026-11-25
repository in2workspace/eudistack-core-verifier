package es.in2.vcverifier.oauth2.infrastructure.config;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CacheStoreConfigTest {

    @Mock
    private BackendConfig backendConfig;

    @Nested
    @DisplayName("cacheStoreForOAuth2AuthorizationRequest")
    class PendingLoginCache {

        @Test
        void cacheStoreForOAuth2AuthorizationRequest_pendingLogin_isKeptForThePendingLoginRetention() {
            // Arrange
            when(backendConfig.getPendingLoginRetentionSeconds()).thenReturn(1L);
            CacheStoreConfig config = new CacheStoreConfig(backendConfig);
            OAuth2AuthorizationRequest login = OAuth2AuthorizationRequest.authorizationCode()
                    .authorizationUri("https://verifier.example.com")
                    .clientId("client")
                    .redirectUri("https://rp.example.com/cb")
                    .state("state-1")
                    .build();

            // Act
            CacheStore<OAuth2AuthorizationRequest> cache = config.cacheStoreForOAuth2AuthorizationRequest();
            cache.add("state-1", login);

            // Assert
            assertThat(cache.getIfPresent("state-1")).isSameAs(login);
            await().atMost(Duration.ofSeconds(5))
                    .untilAsserted(() -> assertThat(cache.getIfPresent("state-1")).isNull());
            verify(backendConfig).getPendingLoginRetentionSeconds();
        }
    }
}
