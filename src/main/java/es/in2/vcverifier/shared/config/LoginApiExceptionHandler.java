package es.in2.vcverifier.shared.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(annotations = LoginApi.class)
public class LoginApiExceptionHandler {

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Object> unreadableBody(HttpServletRequest request) {
        return LoginApiProblems.invalidRequest(HttpStatus.BAD_REQUEST, "The request body is not valid.", null, request);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<Object> missingParameter(MissingServletRequestParameterException ex, HttpServletRequest request) {
        return LoginApiProblems.invalidRequest(HttpStatus.BAD_REQUEST, "A required parameter is missing.",
                ex.getParameterName(), request);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Object> wrongParameter(HttpServletRequest request) {
        return LoginApiProblems.invalidRequest(HttpStatus.BAD_REQUEST, "A parameter is not valid.", null, request);
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<Object> unsupportedMediaType(HttpServletRequest request) {
        return LoginApiProblems.invalidRequest(HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                "The request body must be application/json.", null, request);
    }
}
