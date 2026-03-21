package es.in2.vcverifier.oauth2.infrastructure.controller;

import es.in2.vcverifier.oauth2.infrastructure.adapter.SseEmitterStore;
import es.in2.vcverifier.shared.config.BackendConfig;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Login", description = "SSE-based login events")
public class LoginSseController {

    private final SseEmitterStore sseEmitterStore;
    private final BackendConfig backendConfig;

    @Operation(
            summary = "Subscribe to login events via SSE",
            description = "Server-Sent Events stream for cross-device QR login flow. "
                    + "Sends redirect URL when wallet completes presentation")
    @ApiResponse(responseCode = "200", description = "SSE event stream")
    @ApiResponse(responseCode = "408", description = "Login timeout")
    @GetMapping(value = "/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter subscribe(
            @Parameter(description = "OAuth2 state parameter", required = true)
            @RequestParam String state) {
        long timeoutMs = backendConfig.getLoginTimeoutSeconds() * 1000L;
        return sseEmitterStore.create(state, timeoutMs);
    }
}
