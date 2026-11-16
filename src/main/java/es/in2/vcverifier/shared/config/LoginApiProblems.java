package es.in2.vcverifier.shared.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;

import java.net.URI;
import java.util.List;

public final class LoginApiProblems {

    public static final String INVALID_REQUEST = "invalid_request";
    private static final String INVALID_REQUEST_TITLE = "Invalid request";
    private static final String VIOLATIONS = "violations";
    private static final String REQUIRED = "required";

    public record Violation(String field, String message) {
    }

    private LoginApiProblems() {
    }

    public static ResponseEntity.BodyBuilder response(HttpStatus status) {
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_PROBLEM_JSON);
    }

    public static ResponseEntity<Object> problem(HttpStatus status, String type, String title, String detail,
                                                 HttpServletRequest request) {
        return response(status).body(body(status, type, title, detail, request));
    }

    public static ProblemDetail body(HttpStatus status, String type, String title, String detail,
                                     HttpServletRequest request) {
        ProblemDetail body = ProblemDetail.forStatusAndDetail(status, detail);
        body.setType(URI.create(type));
        body.setTitle(title);
        body.setInstance(URI.create(request.getRequestURI()));
        return body;
    }

    public static ResponseEntity<Object> invalidRequest(HttpStatus status, String detail, String requiredField,
                                                        HttpServletRequest request) {
        ProblemDetail body = body(status, INVALID_REQUEST, INVALID_REQUEST_TITLE, detail, request);
        if (requiredField != null) {
            body.setProperty(VIOLATIONS, List.of(new Violation(requiredField, REQUIRED)));
        }
        return response(status).body(body);
    }
}
