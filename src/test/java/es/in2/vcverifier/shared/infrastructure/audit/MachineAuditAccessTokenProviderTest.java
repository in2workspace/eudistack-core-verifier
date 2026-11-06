package es.in2.vcverifier.shared.infrastructure.audit;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class MachineAuditAccessTokenProviderTest {

    private static final String TOKEN_URL = "http://verifier.internal/verifier/oidc/token";
    private static final String CLIENT_ID = "did:key:zMachine";

    private MockRestServiceServer server;
    private MutableClock clock;
    private MachineAuditAccessTokenProvider provider;

    @BeforeEach
    void setUp() throws Exception {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        clock = new MutableClock(Instant.parse("2026-11-06T10:00:00Z"));
        MachineClientAssertionFactory factory = new MachineClientAssertionFactory(CLIENT_ID, "a.b.c",
                new ECKeyGenerator(Curve.P_256).generate().toJSONString(),
                "https://dome.dev.eudistack.net/verifier", clock);
        provider = new MachineAuditAccessTokenProvider(builder.build(), clock, TOKEN_URL, "dome", CLIENT_ID, factory);
    }

    private static String tokenResponse(String token, long expiresIn) {
        return "{\"access_token\":\"" + token + "\",\"token_type\":\"Bearer\",\"expires_in\":" + expiresIn + "}";
    }

    @Test
    void accessToken_asksTheVerifierAsAMachineForTheTenantAndReturnsTheToken() {
        // Arrange
        server.expect(once(), requestTo(TOKEN_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("X-Tenant", "dome"))
                .andExpect(content().formDataContains(Map.of(
                        "grant_type", "client_credentials",
                        "client_id", CLIENT_ID,
                        "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")))
                .andRespond(withSuccess(tokenResponse("token-1", 899), MediaType.APPLICATION_JSON));

        // Act
        String token = provider.accessToken(null);

        // Assert
        assertEquals("token-1", token);
        server.verify();
    }

    @Test
    void accessToken_stillValid_reusesItWithoutAskingAgain() {
        // Arrange
        server.expect(once(), requestTo(TOKEN_URL))
                .andRespond(withSuccess(tokenResponse("token-1", 899), MediaType.APPLICATION_JSON));
        provider.accessToken(null);
        clock.advance(Duration.ofMinutes(10));

        // Act
        String token = provider.accessToken(null);

        // Assert
        assertEquals("token-1", token);
        server.verify();
    }

    @Test
    void accessToken_aboutToExpire_asksForANewOne() {
        // Arrange
        server.expect(once(), requestTo(TOKEN_URL))
                .andRespond(withSuccess(tokenResponse("token-1", 899), MediaType.APPLICATION_JSON));
        server.expect(once(), requestTo(TOKEN_URL))
                .andRespond(withSuccess(tokenResponse("token-2", 899), MediaType.APPLICATION_JSON));
        provider.accessToken(null);
        clock.advance(Duration.ofSeconds(899 - 59));

        // Act
        String token = provider.accessToken(null);

        // Assert
        assertEquals("token-2", token);
        server.verify();
    }

    @Test
    void refreshAccessToken_alwaysAsksAgainEvenIfTheCachedOneHasNotExpired() {
        // Arrange
        server.expect(once(), requestTo(TOKEN_URL))
                .andRespond(withSuccess(tokenResponse("token-1", 899), MediaType.APPLICATION_JSON));
        server.expect(once(), requestTo(TOKEN_URL))
                .andRespond(withSuccess(tokenResponse("token-2", 899), MediaType.APPLICATION_JSON));
        provider.accessToken(null);

        // Act
        String refreshed = provider.refreshAccessToken(null);

        // Assert
        assertEquals("token-2", refreshed);
        assertEquals("token-2", provider.accessToken(null));
        server.verify();
    }

    @Test
    void accessToken_responseWithoutAccessToken_fails() {
        server.expect(once(), requestTo(TOKEN_URL))
                .andRespond(withSuccess("{\"token_type\":\"Bearer\"}", MediaType.APPLICATION_JSON));

        assertThrows(IllegalStateException.class, () -> provider.accessToken(null));
    }

    @Test
    void accessToken_verifierRejectsTheMachine_failsWithoutEchoingTheResponse() {
        // Arrange
        server.expect(once(), requestTo(TOKEN_URL))
                .andRespond(withStatus(HttpStatus.UNAUTHORIZED).body("{\"detail\":\"secret-detail\"}")
                        .contentType(MediaType.APPLICATION_JSON));

        // Act
        IllegalStateException error = assertThrows(IllegalStateException.class, () -> provider.accessToken(null));

        // Assert
        assertTrue(error.getMessage().contains("did not issue an access token"));
        assertFalse(error.getMessage().contains("secret-detail"));
    }

    @Test
    void constructor_withoutATenant_failsBecauseTheVerifierResolvesTheMachineByIt() {
        MachineClientAssertionFactory factory = null;

        assertThrows(IllegalArgumentException.class, () -> new MachineAuditAccessTokenProvider(
                RestClient.create(), clock, TOKEN_URL, " ", CLIENT_ID, factory));
    }

    @Test
    void constructor_withoutATokenUrl_failsNamingTheVariable() {
        MachineClientAssertionFactory factory = null;

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new MachineAuditAccessTokenProvider(RestClient.create(), clock, "", "dome", CLIENT_ID, factory));

        assertEquals("AUDIT_M2M_TOKEN_URL is not set", error.getMessage());
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
