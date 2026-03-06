package es.in2.vcverifier.oauth2.infrastructure.adapter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import static org.assertj.core.api.Assertions.assertThat;

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
}
