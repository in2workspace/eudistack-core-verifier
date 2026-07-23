package es.in2.vcverifier.oauth2.infrastructure.config;

import com.fasterxml.jackson.databind.JsonNode;
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

    // Snapshot of the resolved VC claims from establishment, keyed by sso_session.id, so a
    // prompt=none reuse (which never re-presents a VP) can still mint a valid id_token without
    // storing claims in the sso_session DB row itself (architecture.md §6.1 / ADR-104). TTL is a
    // safe upper bound set to the maximum configurable SSO absolute TTL (ADR-106: 24h) — CacheStore
    // has a single expiry per instance, so it cannot track each tenant's shorter configured TTL
    // exactly; actual usability is always gated by the authoritative sso_session row still being
    // ACTIVE (ReuseSsoSessionWorkflowImpl checks that first), so an entry outliving its own
    // session's shorter TTL is inert, never a security issue by itself.
    @Bean
    public CacheStore<JsonNode> cacheStoreForSsoSessionCredential() {
        return new CacheStore<>(24, TimeUnit.HOURS, 5_000L);
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
