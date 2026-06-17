package es.in2.vcverifier.sso.infrastructure.web;

import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.exception.SsoConfigInconsistentException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class SsoExceptionHandler {

    @ExceptionHandler(SsoConfigInconsistentException.class)
    public ResponseEntity<Map<String, Object>> handle() {

        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of(
                        "error", "access_denied",
                        "code", "sso_establish_failed"
                ));
    }
}
