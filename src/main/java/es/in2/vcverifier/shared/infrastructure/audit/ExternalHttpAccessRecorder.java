package es.in2.vcverifier.shared.infrastructure.audit;

import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditEventType;
import es.in2.vcverifier.shared.domain.model.audit.ExternalSystemTarget;
import es.in2.vcverifier.shared.domain.port.AuditTrailPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Sends an HTTP request to a third party and records an {@code ExternalSystemAccess} event around it. The
 * request, its response and any error are exactly the ones of {@link HttpClient#send}: recording changes
 * nothing for the caller.
 *
 * <p>The event goes in a transaction of its own, best effort: the call has already happened, and a broken
 * audit channel must neither turn an answer into a failure nor hide the call's own error.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ExternalHttpAccessRecorder {

    private static final String PLATFORM_TENANT = "platform";

    private final AuditTrailPort auditTrail;

    /** For a call made while serving a request, which carries the tenant of the audit context. */
    public <T> HttpResponse<T> send(ExternalSystemTarget target, String operation, HttpClient client,
                                    HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        return sendRecording(target, operation, client, request, handler, false);
    }

    /**
     * For a call made by the process itself, with no request behind it (a scheduled refresh of a global
     * registry). It belongs to no tenant, so it is recorded under the platform.
     */
    public <T> HttpResponse<T> sendAsPlatform(ExternalSystemTarget target, String operation, HttpClient client,
                                              HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        return sendRecording(target, operation, client, request, handler, true);
    }

    private <T> HttpResponse<T> sendRecording(ExternalSystemTarget target, String operation, HttpClient client,
                                              HttpRequest request, HttpResponse.BodyHandler<T> handler,
                                              boolean asPlatform) throws IOException, InterruptedException {
        long startedAt = System.nanoTime();
        HttpResponse<T> response;
        try {
            response = client.send(request, handler);
        } catch (IOException | InterruptedException | RuntimeException error) {
            stage(target, operation, startedAt, Optional.of(ExternalFailureClassifier.reasonOf(error)), asPlatform);
            throw error;
        }
        stage(target, operation, startedAt, ExternalFailureClassifier.reasonOfStatus(response.statusCode()), asPlatform);
        return response;
    }

    /** Never fails the caller: building the entry is as much a part of the audit as staging it. */
    private void stage(ExternalSystemTarget target, String operation, long startedAt, Optional<String> reason,
                       boolean asPlatform) {
        try {
            stageEntry(target, operation, startedAt, reason, asPlatform);
        } catch (RuntimeException auditError) {
            log.warn("action=auditExternalSystemAccess status=skipped error={}", auditError.toString());
        }
    }

    private void stageEntry(ExternalSystemTarget target, String operation, long startedAt, Optional<String> reason,
                        boolean asPlatform) {
        long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);
        Map<String, Object> details = Map.of(
                "system_type", target.systemType(),
                "system", target.system(),
                "operation", operation,
                "authentication_method", target.authenticationMethod(),
                "duration_ms", durationMs);
        String resource = "external-system:" + target.system();
        AuditEntry entry = reason
                .map(failure -> AuditEntry.forReason(AuditEventType.EXTERNAL_SYSTEM_ACCESS, resource, failure, details))
                .orElseGet(() -> AuditEntry.success(AuditEventType.EXTERNAL_SYSTEM_ACCESS, resource, details));
        if (asPlatform) {
            auditTrail.asSystem(PLATFORM_TENANT, AuditEventType.SOURCE, () -> {
                auditTrail.stageBestEffort(entry);
                return null;
            });
        } else {
            auditTrail.stageBestEffort(entry);
        }
    }
}
