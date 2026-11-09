package es.in2.vcverifier.shared.infrastructure.audit;

import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import es.in2.vcverifier.shared.domain.model.audit.ExternalSystemTarget;
import es.in2.vcverifier.shared.domain.port.RecordingAuditTrail;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ExternalHttpAccessRecorderTest {

    private static final HttpRequest REQUEST = HttpRequest.newBuilder(URI.create("https://trusted.example.com/issuers/1")).build();

    private final RecordingAuditTrail auditTrail = new RecordingAuditTrail();
    private final ExternalHttpAccessRecorder recorder = new ExternalHttpAccessRecorder(auditTrail);
    private final HttpClient client = mock(HttpClient.class);

    @SuppressWarnings("unchecked")
    @Test
    void send_serverAnswers_returnsTheResponseAndStagesTheAccess() throws Exception {
        // Arrange
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(response);

        // Act
        HttpResponse<String> answered = recorder.send(ExternalSystemTarget.trustedList("trusted.example.com"),
                "issuers/{id}", client, REQUEST, HttpResponse.BodyHandlers.ofString());

        // Assert
        assertSame(response, answered);
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditResult.SUCCESS, entry.result());
    }

    @SuppressWarnings("unchecked")
    @Test
    void send_auditEntryCannotBeBuilt_stillRethrowsTheOriginalError() throws Exception {
        // Arrange
        IOException original = new IOException("connection refused");
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenThrow(original);
        ExternalSystemTarget withoutHost = ExternalSystemTarget.trustedList(null);

        // Act
        IOException thrown = assertThrows(IOException.class, () -> recorder.send(
                withoutHost, "issuers/{id}", client, REQUEST, HttpResponse.BodyHandlers.ofString()));

        // Assert
        assertSame(original, thrown);
        assertTrue(auditTrail.all().isEmpty());
    }
}
