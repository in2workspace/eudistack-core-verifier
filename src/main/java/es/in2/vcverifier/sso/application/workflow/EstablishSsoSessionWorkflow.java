package es.in2.vcverifier.sso.application.workflow;


import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Application Workflow:
 * Establish SSO Session
 */
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

    /**
     * Executes SSO session establishment
     */
    public SsoSessionCookieDescriptor execute(Command command) {

        Objects.requireNonNull(command);

        // ------------------------------------------------------------
        // ES-03 Fail-closed: tenant config validation
        // ------------------------------------------------------------
        var configOpt = tenantSsoConfigPort.getByTenant(command.tenant());

        if (configOpt.isEmpty() || !configOpt.get().ssoEnabled()) {
            auditPort.publish(new SsoAuditEvent(
                    SsoAuditEvent.EventType.SSO_CONFIG_INCONSISTENT,
                    command.tenant(),
                    command.clientId(),
                    null,
                    "SSO is disabled or misconfigured",
                    command.correlationId(),
                    Instant.now(clock)
            ));
            throw new SsoConfigInconsistentException("SSO is disabled or misconfigured for tenant " + command.tenant());
        }

        // ------------------------------------------------------------
        // AD-3: holderHash = SHA-256(sub)
        // ------------------------------------------------------------
        String holderHash = hashingService.sha256(command.sub());

        Instant now = Instant.now(clock);

        // ------------------------------------------------------------
        // EC-01: supersede active session for (tenant, holderHash)
        // ------------------------------------------------------------
        sessionRepositoryPort.supersedeActive(command.tenant(), holderHash);

        // ------------------------------------------------------------
        // Create new session
        // ------------------------------------------------------------

        SsoSession session = SsoSession.establish(
                command.tenant(),
                holderHash,
                DEFAULT_SESSION_TTL
        );

        sessionRepositoryPort.save(session);

        // ------------------------------------------------------------
        // AC-05: emit event
        // ------------------------------------------------------------
        auditPort.publish(new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED,
                command.tenant(),
                command.clientId(),
                holderHash,
                "SUCCESS",
                command.correlationId(),
                now
        ));

        // ------------------------------------------------------------
        // Return cookie descriptor
        // ------------------------------------------------------------
        return new SsoSessionCookieDescriptor(
                "SSO_SESSION",
                session.getId().getValue().toString(),
                session.getExpiresAt()
        );
    }

    // ============================================================
    // COMMAND DTO (input)
    // ============================================================
    public record Command(
            String tenant,
            String sub,
            String clientId,
            String correlationId
    ) {}

    // ============================================================
    // COOKIE DESCRIPTOR (output)
    // ============================================================
    public record SsoSessionCookieDescriptor(
            String cookieName,
            String value,
            Instant expiresAt
    ) {}

    // ============================================================
    // EXCEPTION (domain/application boundary)
    // ============================================================
    public static class SsoConfigInconsistentException extends RuntimeException {
        public SsoConfigInconsistentException(String message) {
            super(message);
        }
    }
}
