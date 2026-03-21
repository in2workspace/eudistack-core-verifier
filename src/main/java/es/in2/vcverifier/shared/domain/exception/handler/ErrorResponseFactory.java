package es.in2.vcverifier.shared.domain.exception.handler;

import es.in2.vcverifier.shared.domain.model.GlobalErrorMessage;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Component
public class ErrorResponseFactory {

    /**
     * SEC-13: Handles an exception without ever leaking the exception message to the client.
     */
    public GlobalErrorMessage handleSafe(
            Exception ex, HttpServletRequest request,
            String type, String title, HttpStatus status, String detail
    ) {
        return buildError(type, title, status, detail, ex, request);
    }

    private GlobalErrorMessage buildError(
            String type, String title, HttpStatus httpStatus, String detail,
            Exception ex, HttpServletRequest request
    ) {
        String instance = UUID.randomUUID().toString();
        String path = request != null ? request.getRequestURI() : "";
        log.error("instance={} path={} status={} ex={} detail={}",
                instance, path, httpStatus.value(), ex.getClass().getName(), detail);
        return new GlobalErrorMessage(type, title, httpStatus.value(), detail, instance);
    }
}
