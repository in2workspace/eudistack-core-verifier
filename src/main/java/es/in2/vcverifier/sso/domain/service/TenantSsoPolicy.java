package es.in2.vcverifier.sso.domain.service;

import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/**
 * Política de dominio SSO: decide si una sesión puede reutilizarse
 * evaluando 3 condiciones AND en orden AD-2.
 */
@Component
public class TenantSsoPolicy {

    private static final Logger log = LoggerFactory.getLogger(TenantSsoPolicy.class);

    // ----------------------------------------------------------------
    // Rejection reason (EC-01): tipado para que el workflow mapee
    // al código OIDC correcto sin acoplar esta clase a OIDC.
    // ----------------------------------------------------------------

    public enum RejectReason {
        /** Sesión inexistente, expirada o inválida → login_required (US-03). */
        REJECT_SESSION,
        /** Cliente fuera del catálogo SSO del tenant → interaction_required (US-05). */
        REJECT_CATALOG
    }

    // ----------------------------------------------------------------
    // Decision sealed type
    // ----------------------------------------------------------------

    public sealed interface Decision
            permits Decision.Allowed, Decision.Rejected {

        record Allowed() implements Decision {}

        record Rejected(RejectReason reason) implements Decision {}

        static Decision allowed() {
            return new Allowed();
        }

        static Decision rejected(RejectReason reason) {
            return new Rejected(reason);
        }
    }

    // ----------------------------------------------------------------
    // Fields
    // ----------------------------------------------------------------

    private final RegisteredClientRepository clientRepository;
    private final Clock clock;

    public TenantSsoPolicy(RegisteredClientRepository clientRepository, Clock clock) {
        this.clientRepository = Objects.requireNonNull(clientRepository, "clientRepository must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    // ----------------------------------------------------------------
    // Evaluation: 3 condiciones AND en orden AD-2
    // ----------------------------------------------------------------

    /**
     * Evalúa si la sesión SSO puede reutilizarse para el clientId dado.
     *
     * <ol>
     *   <li>clientId es un cliente OAuth2 registrado (fail → REJECT_SESSION).</li>
     *   <li>Sesión vigente (absolute + idle TTL) (fail → REJECT_SESSION, US-03).</li>
     *   <li>catálogo del tenant contiene el clientId (fail → REJECT_CATALOG, US-05).</li>
     * </ol>
     */
    public Decision evaluate(
            String clientId,
            SsoSession session,
            SsoSessionTtl ttl,
            TenantSsoCatalog catalog
    ) {
        Objects.requireNonNull(clientId, "clientId must not be null");
        Objects.requireNonNull(session, "session must not be null");
        Objects.requireNonNull(ttl, "ttl must not be null");
        Objects.requireNonNull(catalog, "catalog must not be null");

        // (1) Cliente registrado en el Authorization Server
        if (clientRepository.findByClientId(clientId) == null) {
            log.debug("event=sso_policy_reject reason=client_not_registered clientId={}", clientId);
            return Decision.rejected(RejectReason.REJECT_SESSION);
        }

        // (2) Sesión vigente (absolute + idle)
        Instant now = Instant.now(clock);
        if (!session.isValid(now, ttl.idle())) {
            log.debug("event=sso_policy_reject reason=session_invalid clientId={}", clientId);
            return Decision.rejected(RejectReason.REJECT_SESSION);
        }

        // (3) Catálogo SSO del tenant (AC-03 fail-closed garantizado por TenantSsoCatalog)
        if (!catalog.contains(clientId)) {
            log.debug("event=sso_policy_reject reason=catalog_miss clientId={}", clientId);
            return Decision.rejected(RejectReason.REJECT_CATALOG);
        }

        return Decision.allowed();
    }
}
