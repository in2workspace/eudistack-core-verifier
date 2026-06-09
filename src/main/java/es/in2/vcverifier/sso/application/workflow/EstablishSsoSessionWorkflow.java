package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

public class EstablishSsoSessionWorkflow {

    private static final Duration DEFAULT_SESSION_TTL = Duration.ofHours(8);

    private final TenantSsoConfigPort tenantSsoConfigPort;
    private final SsoSessionRepositoryPort sessionRepositoryPort;
    private final SsoAuditPort auditPort;
    private final HashingService hashingService;
    private final Clock clock;

    public EstablishSsoSessionWorkflow(
            TenantSsoConfigPort tenantSsoConfigPort,
            SsoSessionRepositoryPort sessionRepositoryPort,
            SsoAuditPort auditPort,
            HashingService hashingService,
            Clock clock
    ) {
        this.tenantSsoConfigPort = tenantSsoConfigPort;
        this.sessionRepositoryPort = sessionRepositoryPort;
        this.auditPort = auditPort;
        this.hashingService = hashingService;
        this.clock = clock;
    }

    public SsoSessionCookieDescriptor execute(SsoSessionCommand command) {

        Objects.requireNonNull(command);

        var configOpt = tenantSsoConfigPort.getByTenant(command.tenant());

        if (configOpt.isEmpty() || !configOpt.get().ssoEnabled()) {

            auditPort.publish(new SsoAuditEvent(
                    SsoAuditEvent.EventType.SSO_CONFIG_INCONSISTENT,
                    command.tenant(),
                    command.clientId(),
                    null,
                    "SSO disabled",
                    command.correlationId(),
                    Instant.now(clock)
            ));

            throw new SsoConfigInconsistentException("SSO disabled for tenant " + command.tenant());
        }

        String holderHash = hashingService.sha256(command.sub());

        Instant now = Instant.now(clock);

        sessionRepositoryPort.supersedeActive(command.tenant(), holderHash);

        SsoSession session = SsoSession.establish(
                command.tenant(),
                holderHash,
                DEFAULT_SESSION_TTL
        );

        sessionRepositoryPort.save(session);

        auditPort.publish(new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED,
                command.tenant(),
                command.clientId(),
                holderHash,
                "SUCCESS",
                command.correlationId(),
                now
        ));

        return new SsoSessionCookieDescriptor(
                "SSO_SESSION",
                session.getId().getValue().toString(),
                session.getExpiresAt()
        );
    }

    public record SsoSessionCookieDescriptor(
            String cookieName,
            String value,
            Instant expiresAt
    ) {}

    public static class SsoConfigInconsistentException extends RuntimeException {
        public SsoConfigInconsistentException(String message) {
            super(message);
        }
    }
}