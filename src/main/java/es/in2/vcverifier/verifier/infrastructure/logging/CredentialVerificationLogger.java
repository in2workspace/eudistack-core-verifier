package es.in2.vcverifier.verifier.infrastructure.logging;

import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.verifier.domain.port.CredentialVerificationLoggerPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Component
@Slf4j
public class CredentialVerificationLogger implements CredentialVerificationLoggerPort {

    private static final String EVENT = "business.credential.verified";
    private static final String UNKNOWN = "unknown";

    @Override
    public void logVerifiedOk(String configurationId) {
        log.info("event={} tenant={} configurationId={} outcome=ok",
                EVENT, currentTenant(), safe(configurationId));
    }

    @Override
    public void logVerifiedError(String configurationId, Throwable error) {
        log.warn("event={} tenant={} configurationId={} outcome=error errorType={}",
                EVENT, currentTenant(), safe(configurationId), errorType(error));
    }

    private static String errorType(Throwable error) {
        return error == null ? UNKNOWN : error.getClass().getSimpleName();
    }

    private String currentTenant() {
        try {
            ServletRequestAttributes attributes =
                    (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            return safe(attributes == null ? null : TenantDomainFilter.getCurrentTenant(attributes.getRequest()));
        } catch (Exception ex) {
            log.debug("Unable to resolve tenant domain from request context. Falling back to unknown", ex);
            return UNKNOWN;
        }
    }

    private static String safe(String value) {
        return (value == null || value.isBlank()) ? UNKNOWN : value;
    }
}
