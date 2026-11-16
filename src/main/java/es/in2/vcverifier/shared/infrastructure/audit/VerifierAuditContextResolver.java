package es.in2.vcverifier.shared.infrastructure.audit;

import com.eudistack.auditoria.domain.AuditActor;
import com.eudistack.auditoria.domain.AuditContext;
import com.eudistack.auditoria.port.AuditContextResolver;
import es.in2.vcverifier.oauth2.infrastructure.filter.UnregisteredM2MClientAuthenticationConverter;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.domain.model.audit.AuditEventType;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Tells the audit starter who is acting in a request: the tenant the tenant filter resolved and the caller,
 * which is a system, the authenticated client or the Verifier itself when nobody has authenticated yet. A
 * request without a tenant has no context.
 */
@Component
@ConditionalOnBooleanProperty("auditoria.publisher.enabled")
public class VerifierAuditContextResolver implements AuditContextResolver {

    @Override
    public Optional<AuditContext> resolve(HttpServletRequest request, @Nullable Authentication authentication) {
        if (!(request.getAttribute(TenantDomainFilter.TENANT_ATTRIBUTE) instanceof String tenant)) {
            return Optional.empty();
        }
        return Optional.of(new AuditContext(tenant, null, null, AuditActor.system(actorIdOf(authentication))));
    }

    /**
     * The name of a client that authenticated, or the Verifier itself. A machine that is not registered is
     * marked as authenticated before its attestation is validated, with the {@code client_id} it wrote, so it
     * is not trusted as an actor: whoever types a legitimate machine's id would be recorded as it. The
     * accepted authentication names the validated system itself, in its own event.
     */
    private static String actorIdOf(@Nullable Authentication authentication) {
        boolean known = authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)
                && !isUnvalidatedMachine(authentication)
                && authentication.getName() != null && !authentication.getName().isBlank();
        return known ? authentication.getName() : AuditEventType.SOURCE;
    }

    private static boolean isUnvalidatedMachine(Authentication authentication) {
        return authentication instanceof OAuth2ClientAuthenticationToken client
                && UnregisteredM2MClientAuthenticationConverter.UNREGISTERED_VC_METHOD
                .equals(client.getClientAuthenticationMethod());
    }
}
