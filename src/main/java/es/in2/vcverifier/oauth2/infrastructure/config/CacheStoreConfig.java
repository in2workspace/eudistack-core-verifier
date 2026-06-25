package es.in2.vcverifier.oauth2.infrastructure.config;

import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationCodeData;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.oauth2.domain.model.RefreshTokenDataCache;
import es.in2.vcverifier.shared.config.BackendConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static es.in2.vcverifier.shared.domain.util.Constants.JTI_CACHE_TTL_SECONDS;

@Configuration
@RequiredArgsConstructor
public class CacheStoreConfig {

    private final BackendConfig backendConfig;

    @Bean
    public CacheStore<String> cacheForNonceByState() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Bean
    public CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT() {
        return new CacheStore<>(
                backendConfig.getLoginTimeoutSeconds(),
                TimeUnit.SECONDS);
    }

    @Bean
    public CacheStore<RefreshTokenDataCache> cacheStoreForRefreshTokenData() {
        return new CacheStore<>(
                backendConfig.getRefreshTokenExpirationSeconds(),
                TimeUnit.SECONDS);
    }

    @Bean
    public CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Bean
    public CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }

    // JTI cache TTL: 2x access token lifetime (900s) to cover clock skew and retries
    @Bean
    public CacheStore<String> jtiCacheStore() {
        return new CacheStore<>(JTI_CACHE_TTL_SECONDS, TimeUnit.SECONDS);
    }

    // F5: short-lived cache to pass the cryptographically verified holder subject from
    // AuthorizationResponseProcessorService (where signature verification happens) to
    // Oid4vpController (where the SSO session is established). Consumed once; TTL matches
    // the login flow timeout.
    @Bean
    public CacheStore<String> verifiedSubjectByState() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }
    
    @Bean
    public Set<String> allowedClientsOrigins() {
        return Collections.synchronizedSet(new HashSet<>());
    }

    // SEC-S3: maxSize bounded to prevent memory exhaustion; 24h TTL suits CA cert lifetimes
    @Bean
    public CacheStore<List<X509Certificate>> aiaCertCacheStore() {
        return new CacheStore<>(24, TimeUnit.HOURS, 1_000L);
    }

}
