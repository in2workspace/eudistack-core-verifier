package es.in2.vcverifier.shared.infrastructure.audit;

import com.eudistack.auditoria.domain.AuditActor;
import com.eudistack.auditoria.domain.AuditContext;
import com.eudistack.auditoria.port.AuditContextResolver;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.domain.model.audit.AuditEventType;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
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

    private static String actorIdOf(@Nullable Authentication authentication) {
        boolean known = authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)
                && authentication.getName() != null && !authentication.getName().isBlank();
        return known ? authentication.getName() : AuditEventType.SOURCE;
    }
}
