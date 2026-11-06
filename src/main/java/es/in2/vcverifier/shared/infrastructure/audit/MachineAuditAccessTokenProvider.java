package es.in2.vcverifier.shared.infrastructure.audit;

import com.eudistack.auditoria.port.AuditAccessTokenProvider;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Access token of the Verifier for the Audit API, obtained as the system it is (DT-002 §3.8): the service
 * authenticates against the Verifier's token endpoint with its machine attestation ({@code client_credentials}
 * plus a {@code client_assertion}) and uses the token it gets until shortly before it expires. The bearer is
 * never configuration.
 *
 * <p>The audience cannot be requested: the Verifier puts its own URL in the {@code aud} of a machine token, so
 * that is the audience the Audit API has to expect.
 */
@Component
@ConditionalOnBooleanProperty("auditoria.dispatcher.enabled")
public class MachineAuditAccessTokenProvider implements AuditAccessTokenProvider {

    private static final String X_TENANT_HEADER = "X-Tenant";
    private static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    /** The token is renewed this long before it expires, so the dispatcher never posts with one about to lapse. */
    private static final Duration EXPIRY_MARGIN = Duration.ofSeconds(60);
    /** Lifetime assumed when the response does not say; short on purpose. */
    private static final Duration DEFAULT_LIFETIME = Duration.ofMinutes(2);

    private final RestClient restClient;
    private final Clock clock;
    private final String tokenUrl;
    private final String tenant;
    private final String clientId;
    private final MachineClientAssertionFactory assertionFactory;

    private CachedToken cached;

    @Autowired
    public MachineAuditAccessTokenProvider(
            @Value("${AUDIT_M2M_TOKEN_URL:}") String tokenUrl,
            @Value("${AUDIT_M2M_TENANT:}") String tenant,
            @Value("${AUDIT_M2M_CLIENT_ID:}") String clientId,
            @Value("${AUDIT_M2M_CREDENTIAL:}") String credential,
            @Value("${AUDIT_M2M_PRIVATE_KEY:}") String privateKey,
            @Value("${AUDIT_M2M_ASSERTION_AUDIENCE:}") String assertionAudience) {
        this(RestClient.create(), Clock.systemUTC(), tokenUrl, tenant, clientId,
                new MachineClientAssertionFactory(clientId, credential, privateKey, assertionAudience,
                        Clock.systemUTC()));
    }

    MachineAuditAccessTokenProvider(RestClient restClient, Clock clock, String tokenUrl, String tenant,
                                    String clientId, MachineClientAssertionFactory assertionFactory) {
        if (tokenUrl == null || tokenUrl.isBlank()) {
            throw new IllegalArgumentException("AUDIT_M2M_TOKEN_URL is not set");
        }
        if (tenant == null || tenant.isBlank()) {
            throw new IllegalArgumentException("AUDIT_M2M_TENANT is not set");
        }
        this.restClient = restClient;
        this.clock = clock;
        this.tokenUrl = tokenUrl;
        this.tenant = tenant;
        this.clientId = clientId;
        this.assertionFactory = assertionFactory;
    }

    @Override
    public synchronized String accessToken(@Nullable String audience) {
        if (cached != null && clock.instant().isBefore(cached.renewAt())) {
            return cached.value();
        }
        return renew();
    }

    /** A 401 means the Audit API no longer accepts the token in hand: ask for a new one, whatever its expiry. */
    @Override
    public synchronized String refreshAccessToken(@Nullable String audience) {
        return renew();
    }

    private String renew() {
        JsonNode response = requestToken();
        String token = response == null ? null : response.path("access_token").asText(null);
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("The Verifier answered without an access token for the Audit API");
        }
        Duration lifetime = response.hasNonNull("expires_in")
                ? Duration.ofSeconds(response.get("expires_in").asLong())
                : DEFAULT_LIFETIME;
        Instant renewAt = clock.instant().plus(lifetime).minus(EXPIRY_MARGIN);
        cached = new CachedToken(token, renewAt);
        return token;
    }

    private JsonNode requestToken() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_assertion_type", CLIENT_ASSERTION_TYPE);
        form.add("client_assertion", assertionFactory.build());
        try {
            return restClient.post()
                    .uri(tokenUrl)
                    .header(X_TENANT_HEADER, tenant)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(JsonNode.class);
        } catch (RestClientException e) {
            // The response body is not logged or chained: it can echo the request.
            throw new IllegalStateException("The Verifier did not issue an access token for the Audit API: "
                    + e.getClass().getSimpleName());
        }
    }

    private record CachedToken(String value, Instant renewAt) {
    }
}
