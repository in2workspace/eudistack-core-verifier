package es.in2.vcverifier.shared.domain.exception.handler;

import es.in2.vcverifier.verifier.domain.exception.BumpedFormatTemporarilyDisabledException;
import es.in2.vcverifier.verifier.domain.exception.LegacyFormatSunsetClosedException;
import es.in2.vcverifier.verifier.domain.exception.UnknownCredentialFormatException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@RequiredArgsConstructor
public class DomeDispatchExceptionHandler {

    private final MeterRegistry meterRegistry;

    @ExceptionHandler(LegacyFormatSunsetClosedException.class)
    public ProblemDetail handleLegacyFormatSunsetClosedException(LegacyFormatSunsetClosedException ex, HttpServletRequest request) {
        incrementLegacyReplayCounter(resolveTenant(request));
        return buildProblemDetail(HttpStatus.GONE, "legacy_format_sunset_closed", "Legacy format is no longer accepted for this tenant");
    }

    @ExceptionHandler(BumpedFormatTemporarilyDisabledException.class)
    public ProblemDetail handleBumpedFormatTemporarilyDisabledException(BumpedFormatTemporarilyDisabledException ex, HttpServletRequest request) {
        return buildProblemDetail(HttpStatus.SERVICE_UNAVAILABLE, "temporarily_unavailable", "Bumped format is temporarily disabled for this tenant");
    }

    @ExceptionHandler(UnknownCredentialFormatException.class)
    public ProblemDetail handleUnknownCredentialFormatException(UnknownCredentialFormatException ex, HttpServletRequest request) {
        return buildProblemDetail(HttpStatus.BAD_REQUEST, "unknown_credential_format", "The credential format could not be resolved");
    }

    private ProblemDetail buildProblemDetail(HttpStatus status, String errorCode, String detail) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(status, detail);
        problemDetail.setTitle(status.getReasonPhrase());
        problemDetail.setProperty("error", errorCode);
        return problemDetail;
    }

    private void incrementLegacyReplayCounter(String tenant) {
        Counter.builder("dome_verifier_legacy_replay_after_sunset_total")
                .description("Legacy format requests after sunset closure")
                .tag("tenant", tenant)
                .register(meterRegistry)
                .increment();
    }

    private String resolveTenant(HttpServletRequest request) {
        if (request == null) {
            return "default";
        }
        Object tenant = request.getAttribute("tenantDomain");
        return tenant instanceof String value && !value.isBlank() ? value : "default";
    }
}
