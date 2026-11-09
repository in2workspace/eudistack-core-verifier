package es.in2.vcverifier.shared.infrastructure.audit;

import com.fasterxml.jackson.core.JsonProcessingException;

import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpTimeoutException;
import java.util.Optional;

/**
 * Maps the outcome of a call to a third party to the {@code ExternalSystemAccess} reason of the catalogue:
 * the error it raised, or the status it answered with. The reason is read from the first cause that
 * identifies the failure, since clients wrap the network error they hit; anything unrecognised is an error
 * response from the system.
 */
public final class ExternalFailureClassifier {

    public static final String AUTHENTICATION_REJECTED = "AuthenticationRejected";
    public static final String ERROR_RESPONSE = "ErrorResponse";
    public static final String INVALID_RESPONSE = "InvalidResponse";
    public static final String TIMEOUT = "Timeout";
    public static final String UNREACHABLE = "Unreachable";

    private static final int MAX_CAUSE_DEPTH = 10;
    private static final int STATUS_UNAUTHORIZED = 401;
    private static final int STATUS_FORBIDDEN = 403;
    private static final int STATUS_NOT_FOUND = 404;

    private ExternalFailureClassifier() {
    }

    public static String reasonOf(Throwable error) {
        Throwable current = error;
        for (int depth = 0; current != null && depth < MAX_CAUSE_DEPTH; depth++) {
            Optional<String> reason = reasonOfSingle(current);
            if (reason.isPresent()) {
                return reason.get();
            }
            current = current.getCause();
        }
        return ERROR_RESPONSE;
    }

    /**
     * The reason for an answer that arrived, or empty when the access succeeded. A 404 is a valid answer
     * (the system was reached and said it does not know the subject), so it is not a failure of the access.
     */
    public static Optional<String> reasonOfStatus(int httpStatus) {
        if (httpStatus == STATUS_UNAUTHORIZED || httpStatus == STATUS_FORBIDDEN) {
            return Optional.of(AUTHENTICATION_REJECTED);
        }
        if ((httpStatus >= 200 && httpStatus < 300) || httpStatus == STATUS_NOT_FOUND) {
            return Optional.empty();
        }
        return Optional.of(ERROR_RESPONSE);
    }

    private static Optional<String> reasonOfSingle(Throwable error) {
        if (error instanceof HttpTimeoutException || error instanceof SocketTimeoutException) {
            return Optional.of(TIMEOUT);
        }
        if (error instanceof ConnectException || error instanceof UnknownHostException
                || error instanceof NoRouteToHostException) {
            return Optional.of(UNREACHABLE);
        }
        if (error instanceof JsonProcessingException) {
            return Optional.of(INVALID_RESPONSE);
        }
        return Optional.empty();
    }
}
