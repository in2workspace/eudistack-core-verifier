package es.in2.vcverifier.sso.domain.exception;

/**
 * EUD-252: a browser-bound login was verified but its browser close step can't be offered (no base
 * URL, the pending login could not be stored). The login fails closed: its code has been revoked
 * and the browser is notified with {@code validation_failed} — the code is never sent over SSE.
 */
public class LoginCompletionUnavailableException extends RuntimeException {

    public LoginCompletionUnavailableException(String message) {
        super(message);
    }
}
