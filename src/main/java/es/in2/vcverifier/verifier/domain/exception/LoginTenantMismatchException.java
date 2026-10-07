package es.in2.vcverifier.verifier.domain.exception;

import java.util.NoSuchElementException;

/**
 * EUD-252: the wallet's authorization response arrived through a tenant different from the one the
 * login was started on. Handled like an unknown state (it is one, for that tenant) — hence the
 * {@link NoSuchElementException} supertype and its existing HTTP mapping.
 */
public class LoginTenantMismatchException extends NoSuchElementException {

    public LoginTenantMismatchException(String message) {
        super(message);
    }
}
