package es.in2.vcverifier.shared.domain.exception.handler;

import es.in2.vcverifier.verifier.domain.exception.*;
import es.in2.vcverifier.oauth2.domain.exception.*;
import es.in2.vcverifier.shared.domain.exception.*;
import es.in2.vcverifier.shared.domain.model.GlobalErrorMessage;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.NoSuchElementException;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public GlobalErrorMessage handleResourceNotFoundException(ResourceNotFoundException ex) {
        log.error("Resource not found", ex);
        return new GlobalErrorMessage("Resource not found", ex.getMessage(), "");
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public GlobalErrorMessage handleNoSuchElementException(NoSuchElementException ex) {
        log.error("Element not found", ex);
        return new GlobalErrorMessage("Element not found", ex.getMessage(), "");
    }

    @ExceptionHandler(CredentialRevokedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public GlobalErrorMessage handleException(CredentialRevokedException ex) {
        log.error("The credential has been revoked: ", ex);
        return new GlobalErrorMessage("Verifiable presentation failed","","");
    }

    @ExceptionHandler(MismatchOrganizationIdentifierException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleException(MismatchOrganizationIdentifierException ex) {
        log.error("The organization identifier of the cert does not match the organization identifier from the credential payload: ", ex);
        return new GlobalErrorMessage("Organization identifier mismatch", ex.getMessage(), "");
    }

    @ExceptionHandler(CredentialExpiredException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleException(CredentialExpiredException ex) {
        log.error("The credential has expired: ", ex);
        return new GlobalErrorMessage("Credential expired", ex.getMessage(), "");
    }

    @ExceptionHandler(CredentialNotActiveException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleException(CredentialNotActiveException ex) {
        log.error("The credential is not active yet: ", ex);
        return new GlobalErrorMessage("Credential not active", ex.getMessage(), "");
    }

    @ExceptionHandler(IssuerNotAuthorizedException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleIssuerNotAuthorizedException(IssuerNotAuthorizedException ex) {
        log.error("Issuer not authorized: {}", ex.getMessage(), ex);
        return new GlobalErrorMessage("Issuer not authorized", ex.getMessage(), "");
    }

    @ExceptionHandler(InvalidCredentialTypeException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleInvalidCredentialTypeException(InvalidCredentialTypeException ex) {
        log.error("Invalid credential type: {}", ex.getMessage(), ex);
        return new GlobalErrorMessage("Invalid credential type", ex.getMessage(), "");
    }

    @ExceptionHandler(JWTClaimMissingException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleJWTClaimMissingException(JWTClaimMissingException ex) {
        log.error("JWT claim missing or invalid: {}", ex.getMessage(), ex);
        return new GlobalErrorMessage("JWT claim error", ex.getMessage(), "");
    }

    @ExceptionHandler(JWTVerificationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleJWTVerificationException(JWTVerificationException ex) {
        log.error("JWT verification failed: {}", ex.getMessage(), ex);
        return new GlobalErrorMessage("JWT verification failed", ex.getMessage(), "");
    }

    @ExceptionHandler(JWTParsingException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleJWTParsingException(JWTParsingException ex) {
        log.error("JWT parsing failed: {}", ex.getMessage(), ex);
        return new GlobalErrorMessage("JWT parsing failed", ex.getMessage(), "");
    }

    @ExceptionHandler(InvalidScopeException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleInvalidScopeException(InvalidScopeException ex) {
        log.error("Cryptographic binding or scope error: {}", ex.getMessage(), ex);
        return new GlobalErrorMessage("Scope/binding error", ex.getMessage(), "");
    }

    @ExceptionHandler(CredentialMappingException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public GlobalErrorMessage handleCredentialMappingException(CredentialMappingException ex) {
        log.error("Credential mapping failed: {}", ex.getMessage(), ex);
        return new GlobalErrorMessage("Credential mapping error", ex.getMessage(), "");
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public GlobalErrorMessage handleException(Exception ex) {
        log.error("An unexpected error occurred: ", ex);
        return new GlobalErrorMessage("Unexpected error", ex.getClass().getSimpleName() + ": " + ex.getMessage(), "");
    }

    @ExceptionHandler(InvalidVPtokenException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleException(InvalidVPtokenException ex, HttpServletRequest request) {
        String contextPath = request.getContextPath();
        log.error("VP token is not valid: {}", ex.getMessage());
        return new GlobalErrorMessage("Invalid VP Token", ex.getMessage(), contextPath);
    }

    @ExceptionHandler(LoginTimeoutException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleException(LoginTimeoutException ex) {
        log.error("Login time has expired ", ex.getMessage());
        return new GlobalErrorMessage("Login time has expired ",ex.getMessage(),"");
    }

    @ExceptionHandler(StatusListCredentialException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public GlobalErrorMessage handleStatusListCredentialException(StatusListCredentialException ex) {
        log.error("Error while handling Status List Credential ", ex.getMessage());
        return new GlobalErrorMessage("Error while handling Status List Credential ",ex.getMessage(),"");
    }
}

