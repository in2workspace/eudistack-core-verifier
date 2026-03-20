package es.in2.vcverifier.oauth2.infrastructure.controller;

import es.in2.vcverifier.oauth2.infrastructure.adapter.SseEmitterStore;
import es.in2.vcverifier.shared.config.BackendConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestController
@RequestMapping("/api/login")
@RequiredArgsConstructor
public class LoginSseController {

    private final SseEmitterStore sseEmitterStore;
    private final BackendConfig backendConfig;

    @GetMapping(value = "/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter subscribe(@RequestParam String state) {
        long timeoutMs = backendConfig.getLoginTimeoutSeconds() * 1000L;
        return sseEmitterStore.create(state, timeoutMs);
    }
}
