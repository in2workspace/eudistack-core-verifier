package es.in2.vcverifier.sso.infrastructure.web;

import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class SsoSessionAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final SsoAuditPort auditPort;

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException, ServletException {

        String correlationId = UUID.randomUUID().toString();

        auditPort.publish(new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED,
                null,
                null,
                null,
                "FAILURE",
                correlationId,
                Instant.now(),
                null
        ));

        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
