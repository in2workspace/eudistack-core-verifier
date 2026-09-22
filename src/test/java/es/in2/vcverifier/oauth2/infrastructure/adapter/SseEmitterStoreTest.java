package es.in2.vcverifier.oauth2.infrastructure.adapter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class SseEmitterStoreTest {

    private SseEmitterStore store;

    @BeforeEach
    void setUp() {
        store = new SseEmitterStore();
    }

    @Test
    void create_returnsEmitter() {
        SseEmitter emitter = store.create("state-1", 60000L);
        assertThat(emitter).isNotNull();
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

            // The emitter must already be removed from the store — send() finds nothing.
            store.send("state-1", "http://redirect.example.com");
            verify(emitter, never()).send(any(SseEmitter.SseEventBuilder.class));
        }
    }
}
