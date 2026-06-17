package es.in2.vcverifier.shared.domain.exception.handler;

import es.in2.vcverifier.shared.domain.model.GlobalErrorMessage;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.exception.SsoConfigInconsistentException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

@Slf4j
@Component
public class ErrorResponseFactory {

    /**
     * Handles safe generic errors (no domain mapping).
     */
    public GlobalErrorMessage handleSafe(
            Exception ex,
            HttpServletRequest request,
            String type,
            String title,
            HttpStatus status,
            String detail
    ) {
        return buildError(type, title, status, detail, ex, request);
    }

    /**
     * Main entry for SSO + global exception mapping.
     */
    public GlobalErrorMessage handle(Exception ex, HttpServletRequest request) {

        // -------------------------
        // SSO CONFIG ERROR
        // -------------------------
        if (ex instanceof SsoConfigInconsistentException) {

            return buildError(
                    "access_denied",
                    "Sso Establish Failed",
                    HttpStatus.FORBIDDEN,
                    "sso_establish_failed",
                    ex,
                    request
            );
        }

        // -------------------------
        // DEFAULT ERROR
        // -------------------------
        return buildError(
                "internal_server_error",
                "Internal server error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "unexpected_error",
                ex,
                request
        );
    }

    /**
     * Core builder (no business logic here).
     */
    private GlobalErrorMessage buildError(
            String type,
            String title,
            HttpStatus httpStatus,
            String detail,
            Exception ex,
            HttpServletRequest request
    ) {

        String instance = UUID.randomUUID().toString();
        String path = request != null ? request.getRequestURI() : "";

        // -------------------------
        // SAFE LOG (NO OVERLOAD ISSUES)
        // -------------------------
        log.error("instance={}", instance);
        log.error("path={}", path);
        log.error("status={}", Optional.of(httpStatus.value()));
        log.error("detail={}", detail);
        log.error("SSO exception", ex);

        return new GlobalErrorMessage(
                type,
                title,
                httpStatus.value(),
                detail,
                instance
        );
    }
}