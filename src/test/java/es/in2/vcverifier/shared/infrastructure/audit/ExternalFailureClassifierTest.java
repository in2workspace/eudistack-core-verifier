package es.in2.vcverifier.shared.infrastructure.audit;

import com.fasterxml.jackson.core.JsonParseException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExternalFailureClassifierTest {

    @Test
    void reasonOf_requestTimeout_returnsTimeout() {
        // Arrange & Act
        String reason = ExternalFailureClassifier.reasonOf(new HttpTimeoutException("request timed out"));

        // Assert
        assertEquals("Timeout", reason);
    }

    @Test
    void reasonOf_connectTimeout_returnsTimeoutAndNotUnreachable() {
        // Arrange & Act
        String reason = ExternalFailureClassifier.reasonOf(new HttpConnectTimeoutException("connect timed out"));

        // Assert
        assertEquals("Timeout", reason);
    }

    @Test
    void reasonOf_socketTimeoutWrappedByAnotherError_returnsTimeout() {
        // Arrange & Act
        String reason = ExternalFailureClassifier.reasonOf(new RuntimeException("wrapped", new SocketTimeoutException("read")));

        // Assert
        assertEquals("Timeout", reason);
    }

    @Test
    void reasonOf_connectionRefused_returnsUnreachable() {
        // Arrange & Act
        String reason = ExternalFailureClassifier.reasonOf(new ConnectException("refused"));

        // Assert
        assertEquals("Unreachable", reason);
    }

    @Test
    void reasonOf_unknownHost_returnsUnreachable() {
        // Arrange & Act
        String reason = ExternalFailureClassifier.reasonOf(new UnknownHostException("registry.example.com"));

        // Assert
        assertEquals("Unreachable", reason);
    }

    @Test
    void reasonOf_unparsableBody_returnsInvalidResponse() {
        // Arrange & Act
        String reason = ExternalFailureClassifier.reasonOf(new JsonParseException(null, "unexpected token"));

        // Assert
        assertEquals("InvalidResponse", reason);
    }

    @Test
    void reasonOf_unrecognisedError_returnsErrorResponse() {
        // Arrange & Act
        String reason = ExternalFailureClassifier.reasonOf(new IllegalStateException("something else"));

        // Assert
        assertEquals("ErrorResponse", reason);
    }

    @ParameterizedTest
    @CsvSource({"200", "204", "404"})
    void reasonOfStatus_answerThatMeansTheAccessWorked_returnsEmpty(int status) {
        // Arrange & Act
        Optional<String> reason = ExternalFailureClassifier.reasonOfStatus(status);

        // Assert
        assertTrue(reason.isEmpty());
    }

    @ParameterizedTest
    @CsvSource({"401", "403"})
    void reasonOfStatus_credentialsRejected_returnsAuthenticationRejected(int status) {
        // Arrange & Act
        Optional<String> reason = ExternalFailureClassifier.reasonOfStatus(status);

        // Assert
        assertEquals("AuthenticationRejected", reason.orElseThrow());
    }

    @ParameterizedTest
    @CsvSource({"400", "429", "500", "503"})
    void reasonOfStatus_otherErrorStatus_returnsErrorResponse(int status) {
        // Arrange & Act
        Optional<String> reason = ExternalFailureClassifier.reasonOfStatus(status);

        // Assert
        assertEquals("ErrorResponse", reason.orElseThrow());
    }
}
