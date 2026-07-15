package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.exception.SsoConfigInconsistentException;
import es.in2.vcverifier.sso.domain.exception.SsoDisabledForTenantException;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;


@Service
public class EstablishSsoSessionWorkflow {

    private static final Logger log =
            LoggerFactory.getLogger(EstablishSsoSessionWorkflow.class);

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

        validateTenantSsoConfiguration(command);

        SsoSessionTtl ttl = tenantSsoConfigPort.resolveTtl(command.tenant());

        String holderHash = hashingService.sha256(command.sub());

        Instant now = Instant.now(clock);
        SsoSession session;

        try {
            sessionRepositoryPort.supersedeActive(command.tenant(), holderHash);

            session = SsoSession.establish(
                    command.tenant(),
                    holderHash,
                    ttl.absolute()
            );

            sessionRepositoryPort.save(session);

        } catch (Exception ex) {

            log.error("Error persisting SSO session for tenant={}", command.tenant(), ex);

            auditPort.publish(new SsoAuditEvent(
                    SsoAuditEvent.EventType.SSO_PERSIST_ERROR,
                    command.tenant(),
                    command.clientId(),
                    holderHash,
                    "PERSIST_ERROR",
                    command.correlationId(),
                    Instant.now(clock)
            ));

            return null; // fail-closed
        }

        // B7: holderHash field in SsoAuditEvent always carries raw sub; SsoAuditAdapter applies SHA-256.
        auditPort.publish(new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED,
                command.tenant(),
                command.clientId(),
                command.sub(),
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

    private void validateTenantSsoConfiguration(SsoSessionCommand command) {
        var config = tenantSsoConfigPort.getByTenant(command.tenant())
                .orElseThrow(() -> {
                    publishMissingConfigAudit(command);
                    return new SsoConfigInconsistentException(
                            "Missing SSO config for tenant " + command.tenant());
                });

        if (!config.ssoEnabled()) {
            log.debug(
                    "event=sso_legacy_tenant tenant={} correlation_id={}",
                    command.tenant(),
                    command.correlationId());

            throw new SsoDisabledForTenantException(command.tenant());
        }
    }
    private void publishMissingConfigAudit(SsoSessionCommand command) {
        auditPort.publish(new SsoAuditEvent(
                SsoAuditEvent.EventType.SSO_CONFIG_INCONSISTENT,
                command.tenant(),
                command.clientId(),
                null,
                "CONFIG_ABSENT",
               command.correlationId(),
                Instant.now(clock)
        ));
    }

    public record SsoSessionCookieDescriptor(
            String cookieName,
            String value,
            Instant expiresAt
    ) {}

}