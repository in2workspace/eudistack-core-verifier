package es.in2.vcverifier.sso.infrastructure.backchannel;

import es.in2.vcverifier.sso.domain.model.DeliveryOutcome;
import es.in2.vcverifier.sso.domain.model.LogoutTarget;
import es.in2.vcverifier.sso.domain.model.LogoutToken;
import es.in2.vcverifier.sso.domain.port.BackChannelLogoutNotifierPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.net.URLEncoder;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * US-06 (Single Logout): adapter de {@link BackChannelLogoutNotifierPort} — cliente HTTP con
 * timeout, retry con backoff exponencial y circuit breaker per {@code client_id}. Firma el
 * {@code logout_token} vía {@link LogoutTokenFactory} y entrega
 * {@code POST backchannel_logout_uri} (form-urlencoded, EC-03/ES-02/ES-03).
 * <p>
 * El dispatch asíncrono (AD-2) lo gestiona el llamador ({@code TerminateSsoSessionWorkflow}
 * vía {@code backChannelLogoutExecutor}); esta clase asume que ya se ejecuta en un hilo
 * dedicado y puede bloquear con {@code Thread.sleep} durante los reintentos sin afectar
 * al hilo de la request del iniciador.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BackChannelLogoutDispatcher implements BackChannelLogoutNotifierPort {

    private static final int MAX_ATTEMPTS = 3;
    private static final long BASE_BACKOFF_MS = 500L;
    private static final long JITTER_MS = 250L;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private static final int FAILURE_THRESHOLD = 5;
    private static final long CIRCUIT_OPEN_MS = 60_000L;

    private final HttpClient httpClient;
    private final LogoutTokenFactory logoutTokenFactory;

    private final ConcurrentHashMap<String, CircuitBreakerState> breakers = new ConcurrentHashMap<>();
    private final Set<String> inFlightDispatches = ConcurrentHashMap.newKeySet();

    @Override
    public DeliveryOutcome notifyLogout(LogoutTarget target, LogoutToken token) {
        String dedupKey = token.sid() + ":" + target.clientId();

        if (!inFlightDispatches.add(dedupKey)) {
            log.warn("backchannel_logout_duplicate_suppressed clientId={} sid={}...",
                    target.clientId(), prefix8(token.sid()));
            return new DeliveryOutcome.Failed(target.clientId(), "duplicate_dispatch_suppressed");
        }

        try {
            CircuitBreakerState breaker = breakers.computeIfAbsent(target.clientId(), id -> new CircuitBreakerState());
            if (isOpen(breaker)) {
                log.warn("backchannel_logout_circuit_open clientId={}", target.clientId());
                return new DeliveryOutcome.Failed(target.clientId(), "circuit_open");
            }

            String logoutTokenJwt = logoutTokenFactory.build(token);
            String reason = "unknown";

            for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
                try {
                    HttpResponse<String> response = sendRequest(target.backchannelLogoutUri(), logoutTokenJwt);
                    if (response.statusCode() == 200) {
                        recordSuccess(breaker);
                        return new DeliveryOutcome.Delivered(target.clientId());
                    }
                    reason = "http_" + response.statusCode();
                } catch (HttpTimeoutException e) {
                    reason = "timeout";
                } catch (IOException e) {
                    reason = "io_error";
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    reason = "interrupted";
                    break;
                }

                if (attempt < MAX_ATTEMPTS) {
                    sleepWithBackoff(attempt);
                }
            }

            recordFailure(breaker);
            log.warn("backchannel_logout_failed clientId={} reason={}", target.clientId(), reason);
            return new DeliveryOutcome.Failed(target.clientId(), reason);

        } finally {
            inFlightDispatches.remove(dedupKey);
        }
    }

    private HttpResponse<String> sendRequest(String uri, String logoutTokenJwt)
            throws IOException, InterruptedException {
        String body = "logout_token=" + URLEncoder.encode(logoutTokenJwt, StandardCharsets.UTF_8);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private void sleepWithBackoff(int attempt) {
        long backoff = BASE_BACKOFF_MS * (1L << (attempt - 1));
        long jitter = ThreadLocalRandom.current().nextLong(-JITTER_MS, JITTER_MS + 1);
        long delay = Math.max(0, backoff + jitter);
        try {
            Thread.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private boolean isOpen(CircuitBreakerState breaker) {
        return breaker.openUntil > System.currentTimeMillis();
    }

    private void recordSuccess(CircuitBreakerState breaker) {
        breaker.failureCounter.set(0);
        breaker.openUntil = 0L;
    }

    private void recordFailure(CircuitBreakerState breaker) {
        int failures = breaker.failureCounter.incrementAndGet();
        if (failures >= FAILURE_THRESHOLD) {
            breaker.openUntil = System.currentTimeMillis() + CIRCUIT_OPEN_MS;
            log.warn("backchannel_logout_circuit_opened_for_ms={} after {} consecutive failures",
                    CIRCUIT_OPEN_MS, failures);
        }
    }

    /** NFR-S-551-02: nunca loggear el session_id completo — solo prefijo 8 chars. */
    private static String prefix8(String s) {
        if (s == null) return "null";
        return s.length() <= 8 ? s : s.substring(0, 8);
    }

    private static final class CircuitBreakerState {
        private final AtomicInteger failureCounter = new AtomicInteger(0);
        private volatile long openUntil = 0L;
    }
}
