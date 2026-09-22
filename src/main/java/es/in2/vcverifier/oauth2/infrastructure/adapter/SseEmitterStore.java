package es.in2.vcverifier.oauth2.infrastructure.adapter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;

@Slf4j
@Component
@RequiredArgsConstructor
public class SseEmitterStore {

    // SEC-F6: Bounded SSE emitter store to prevent connection/memory exhaustion.
    private static final int MAX_CONCURRENT_EMITTERS = 5_000;

    // Keeps the stream producing bytes while it waits for the wallet, so intermediary
    // proxies/CDNs with an idle timeout shorter than the 120s login window (e.g.
    // CloudFront's default 30s origin_read_timeout, retried up to 3x by CloudFront
    // before giving up — ~90s of total silence) never see the connection go quiet and
    // kill it with a 504. That 504 reaches the client as an EventSource error the
    // frontend can't distinguish from a real failure, appearing to freeze the login
    // countdown instead of a clean timeout.
    private static final Duration HEARTBEAT_INTERVAL = Duration.ofSeconds(15);

    private final TaskScheduler taskScheduler;

    private final ConcurrentHashMap<String, SseEmitter> emitters = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ScheduledFuture<?>> heartbeats = new ConcurrentHashMap<>();

    public SseEmitter create(String state, long timeoutMs) {
        if (emitters.size() >= MAX_CONCURRENT_EMITTERS) {
            log.warn("SSE emitter limit reached ({}). Rejecting new connection for state={}...",
                    MAX_CONCURRENT_EMITTERS, state.substring(0, Math.min(8, state.length())));
            throw new IllegalStateException("Too many concurrent SSE connections");
        }
        SseEmitter emitter = new SseEmitter(timeoutMs);
        emitters.put(state, emitter);
        emitter.onCompletion(() -> removeEmitter(state));
        // Without an explicit complete() here, Spring's default async-timeout handling
        // completes the request with a raw 503, which the client's EventSource surfaces
        // as a connection error (racing the client's own independent countdown instead
        // of the expected clean stream close).
        emitter.onTimeout(() -> {
            removeEmitter(state);
            emitter.complete();
        });
        emitter.onError(e -> removeEmitter(state));

        heartbeats.put(state, taskScheduler.scheduleAtFixedRate(
                () -> sendHeartbeat(state, emitter),
                Instant.now().plus(HEARTBEAT_INTERVAL),
                HEARTBEAT_INTERVAL));

        log.debug("SSE emitter created for state={}, timeout={}ms", state, timeoutMs);
        return emitter;
    }

    public void send(String state, String redirectUrl) {
        SseEmitter emitter = removeEmitter(state);
        if (emitter != null) {
            try {
                emitter.send(SseEmitter.event().name("redirect").data(redirectUrl));
                emitter.complete();
                log.debug("SSE redirect event sent for state={}", state);
            } catch (IOException e) {
                log.warn("Failed to send SSE event for state={}: {}", state, e.getMessage());
                emitter.completeWithError(e);
            }
        } else {
            log.warn("No SSE emitter found for state={}", state);
        }
    }

    /**
     * Send validation_failed SSE event to notify client of VP validation failure.
     *
     * @param state OAuth2 state (SSE connection key)
     * @param errorCode Error code (e.g., CREDENTIAL_REVOKED, SIGNATURE_INVALID)
     * @param errorMessage Human-readable error message
     */
    public void sendValidationFailed(String state, String errorCode, String errorMessage) {
        SseEmitter emitter = removeEmitter(state);

        if (emitter != null) {
            try {
                // Build JSON payload with error details
                String payload = String.format(
                    "{\"code\": \"%s\", \"message\": \"%s\"}",
                    errorCode,
                    escapeJson(errorMessage)
                );

                emitter.send(SseEmitter.event()
                    .name("validation_failed")
                    .data(payload));

                emitter.complete();
                log.info("SSE validation_failed event sent for state={}, code={}", state, errorCode);
            } catch (IOException e) {
                log.warn("Failed to send validation_failed SSE for state={}: {}", state, e.getMessage());
                emitter.completeWithError(e);
            }
        } else {
            log.debug("No SSE emitter found for state={} (validation_failed event not sent)", state);
        }
    }

    /**
     * Sends an SSE comment (ignored by {@code EventSource}, never surfaced to application
     * code) purely to keep bytes flowing through any intermediary proxy/CDN. If the client
     * has already disconnected or the emitter has otherwise completed, the send fails and
     * the heartbeat cancels itself instead of retrying against a dead emitter.
     */
    private void sendHeartbeat(String state, SseEmitter emitter) {
        try {
            emitter.send(SseEmitter.event().comment("keep-alive"));
        } catch (IOException | IllegalStateException e) {
            log.debug("Heartbeat failed for state={}, stopping: {}", state, e.getMessage());
            cancelHeartbeat(state);
        }
    }

    private SseEmitter removeEmitter(String state) {
        SseEmitter emitter = emitters.remove(state);
        cancelHeartbeat(state);
        return emitter;
    }

    private void cancelHeartbeat(String state) {
        ScheduledFuture<?> heartbeat = heartbeats.remove(state);
        if (heartbeat != null) {
            heartbeat.cancel(false);
        }
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
    }
}
