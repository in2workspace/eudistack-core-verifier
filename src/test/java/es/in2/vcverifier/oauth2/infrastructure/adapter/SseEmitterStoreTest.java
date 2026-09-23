package es.in2.vcverifier.oauth2.infrastructure.adapter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class SseEmitterStoreTest {

    private TaskScheduler taskScheduler;
    private ScheduledFuture<?> heartbeatFuture;
    private SseEmitterStore store;

    @SuppressWarnings("unchecked")
    @BeforeEach
    void setUp() {
        taskScheduler = mock(TaskScheduler.class);
        heartbeatFuture = mock(ScheduledFuture.class);
        doReturn(heartbeatFuture).when(taskScheduler)
                .scheduleAtFixedRate(any(Runnable.class), any(Instant.class), any(Duration.class));
        store = new SseEmitterStore(taskScheduler);
    }

    @Test
    void create_returnsEmitter() {
        SseEmitter emitter = store.create("state-1", 60000L);
        assertThat(emitter).isNotNull();
    }

    @Test
    void create_schedulesAHeartbeat() {
        store.create("state-1", 60000L);
        verify(taskScheduler).scheduleAtFixedRate(any(Runnable.class), any(Instant.class), any(Duration.class));
    }

    @Test
    void send_completesEmitterAndRemovesIt() {
        store.create("state-1", 60000L);
        // Should not throw
        store.send("state-1", "http://redirect.example.com");
        // Second send should find no emitter (already removed)
        store.send("state-1", "http://redirect.example.com");
    }

    @Test
    void send_cancelsTheHeartbeat() {
        store.create("state-1", 60000L);
        store.send("state-1", "http://redirect.example.com");
        verify(heartbeatFuture).cancel(false);
    }

    @Test
    void send_nonExistentState_doesNotThrow() {
        store.send("unknown-state", "http://redirect.example.com");
    }

    @Test
    void create_multipleStates_independent() {
        SseEmitter e1 = store.create("state-1", 60000L);
        SseEmitter e2 = store.create("state-2", 60000L);
        assertThat(e1).isNotSameAs(e2);
    }

    @Test
    void create_sameStateTwice_replacesPrevious() {
        store.create("state-1", 60000L);
        SseEmitter replacement = store.create("state-1", 60000L);
        assertThat(replacement).isNotNull();
    }

    // Regression: without an explicit complete() in onTimeout, Spring's default
    // async-timeout handling completes the request with a raw 503, which the
    // client's EventSource surfaces as a connection error racing the client's
    // own 120s countdown instead of a clean stream close.
    @Test
    void onTimeout_completesEmitterAndRemovesIt() throws IOException {
        AtomicReference<Runnable> capturedOnTimeout = new AtomicReference<>();

        try (MockedConstruction<SseEmitter> mockedConstruction = mockConstruction(SseEmitter.class)) {
            SseEmitter emitter = store.create("state-1", 60000L);
            assertThat(mockedConstruction.constructed()).containsExactly(emitter);

            // Capture the Runnable SseEmitterStore registered via emitter.onTimeout(...).
            verify(emitter).onTimeout(argThat(runnable -> {
                capturedOnTimeout.set(runnable);
                return true;
            }));

            // Simulate the servlet container invoking the timeout callback.
            capturedOnTimeout.get().run();

            verify(emitter).complete();
            verify(heartbeatFuture).cancel(false);

            // The emitter must already be removed from the store — send() finds nothing.
            store.send("state-1", "http://redirect.example.com");
            verify(emitter, never()).send(any(SseEmitter.SseEventBuilder.class));
        }
    }

    // Regression: an SSE stream with no application data for ~30s+ gets killed by
    // intermediary proxies/CDNs (e.g. CloudFront's default origin_read_timeout,
    // retried up to 3x ≈ 90s of total silence) well before the 120s login window
    // elapses. A periodic heartbeat keeps bytes flowing so that never happens.
    @Test
    void heartbeat_sendsAnSseComment() throws IOException {
        AtomicReference<Runnable> capturedHeartbeat = new AtomicReference<>();
        doReturn(heartbeatFuture).when(taskScheduler).scheduleAtFixedRate(
                argThat(runnable -> {
                    capturedHeartbeat.set(runnable);
                    return true;
                }),
                any(Instant.class), any(Duration.class));

        try (MockedConstruction<SseEmitter> _ = mockConstruction(SseEmitter.class)) {
            SseEmitter emitter = store.create("state-1", 60000L);

            capturedHeartbeat.get().run();

            verify(emitter).send(any(SseEmitter.SseEventBuilder.class));
        }
    }

    @Test
    void heartbeat_stopsItselfWhenTheEmitterIsAlreadyGone() {
        AtomicReference<Runnable> capturedHeartbeat = new AtomicReference<>();
        doReturn(heartbeatFuture).when(taskScheduler).scheduleAtFixedRate(
                argThat(runnable -> {
                    capturedHeartbeat.set(runnable);
                    return true;
                }),
                any(Instant.class), any(Duration.class));

        try (MockedConstruction<SseEmitter> _ = mockConstruction(SseEmitter.class,
                (mock, context) -> doThrow(new IOException("client disconnected"))
                        .when(mock).send(any(SseEmitter.SseEventBuilder.class)))) {
            store.create("state-1", 60000L);

            capturedHeartbeat.get().run();

            verify(heartbeatFuture).cancel(false);
        }
    }

    @Test
    void sendValidationFailed_cancelsTheHeartbeat() {
        store.create("state-1", 60000L);
        store.sendValidationFailed("state-1", "CREDENTIAL_REVOKED", "revoked");
        verify(heartbeatFuture).cancel(false);
    }
}
