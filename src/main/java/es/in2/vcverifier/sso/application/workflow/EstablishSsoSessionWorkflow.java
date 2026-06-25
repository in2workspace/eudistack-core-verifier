package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.exception.SsoConfigInconsistentException;
import es.in2.vcverifier.sso.domain.exception.SsoSessionRepositoryException;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;


@Service
public class EstablishSsoSessionWorkflow {

    private static final Logger log =
            LoggerFactory.getLogger(EstablishSsoSessionWorkflow.class);
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
                    Instant.now(clock),
                    null
            ));
            throw new SsoConfigInconsistentException("SSO not enabled for tenant " + command.tenant());
        }

        String holderHash = hashingService.sha256(command.sub());
        Instant now = Instant.now(clock);
        SsoSession session;

        try {
            session = SsoSession.establish(command.tenant(), holderHash, DEFAULT_SESSION_TTL);
            sessionRepositoryPort.establishAtomically(session);
        } catch (Exception ex) {
            log.error("Error persisting SSO session for tenant={}", command.tenant(), ex);
            auditPort.publish(new SsoAuditEvent(
                    SsoAuditEvent.EventType.SSO_PERSIST_ERROR,
                    command.tenant(),
                    command.clientId(),
                    holderHash,
                    "PERSIST_ERROR",
                    command.correlationId(),
                    Instant.now(clock),
                    null
            ));
            return null; // fail-closed
        }

        String sessionIdPrefix = session.getId().getValue().substring(0, 8);

        auditPort.publish(new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED,
                command.tenant(),
                command.clientId(),
                holderHash,
                "SUCCESS",
                command.correlationId(),
                now,
                sessionIdPrefix
        ));

        return new SsoSessionCookieDescriptor(
                "SSO_SESSION",
                session.getId().getValue(),
                session.getExpiresAt()
        );
    }

    public record SsoSessionCookieDescriptor(
            String cookieName,
            String value,
            Instant expiresAt
    ) {}

}