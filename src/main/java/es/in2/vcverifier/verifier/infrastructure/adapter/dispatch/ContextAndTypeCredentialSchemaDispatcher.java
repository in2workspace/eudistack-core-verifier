package es.in2.vcverifier.verifier.infrastructure.adapter.dispatch;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.verifier.domain.exception.BumpedFormatTemporarilyDisabledException;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.verifier.domain.exception.LegacyFormatSunsetClosedException;
import es.in2.vcverifier.verifier.domain.exception.UnknownCredentialFormatException;
import es.in2.vcverifier.verifier.domain.model.config.TenantDomeConfig;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchReason;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchRule;
import es.in2.vcverifier.verifier.domain.service.CredentialSchemaDispatcher;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import es.in2.vcverifier.verifier.domain.util.CredentialTypeResolver;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.Locale;

@Slf4j
@Component
@RequiredArgsConstructor
public class ContextAndTypeCredentialSchemaDispatcher implements CredentialSchemaDispatcher {

    private static final String VC_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";
    private static final String VC_V1_CONTEXT = "https://www.w3.org/2018/credentials/v1";

    private final List<DispatchRule> dispatchRules;
    private final TenantConfigPort tenantConfigPort;

    @Override
    public DispatchDecision dispatch(JsonNode credential) {
        String configIdFromType = resolveConfigIdFromType(credential);
        CredentialFormat formatFromContext = resolveFormatFromContext(credential);

        if (configIdFromType == null && formatFromContext == null) {
            throw new UnknownCredentialFormatException("Cannot dispatch credential: missing both type/vct and @context");
        }

        if (configIdFromType == null) {
            throw new UnknownCredentialFormatException("Cannot dispatch credential: no credential configuration id could be resolved from type/vct");
        }

        CredentialFormat format = resolveFormatByConfigId(configIdFromType);
        DispatchReason reason = resolveReason(format, formatFromContext);

        TenantDomeConfig tenantConfig = tenantConfigPort.getDomeConfig(resolveTenantDomain());
        if (format == CredentialFormat.LEGACY_V1_1 && !tenantConfig.legacyReadEnabled()) {
            throw new LegacyFormatSunsetClosedException("Legacy format is disabled for the current tenant");
        }
        if (format == CredentialFormat.BUMPED_V2_0 && !tenantConfig.bumpedReadEnabled()) {
            throw new BumpedFormatTemporarilyDisabledException("Bumped format is temporarily disabled for the current tenant");
        }

        return DispatchDecision.permitted(configIdFromType, format, reason);
    }

    private String resolveConfigIdFromType(JsonNode credential) {
        try {
            return CredentialTypeResolver.resolveConfigId(credential);
        } catch (InvalidCredentialTypeException ex) {
            return null;
        }
    }

    private CredentialFormat resolveFormatByConfigId(String credentialConfigurationId) {
        return dispatchRules.stream()
                .filter(rule -> rule.credentialConfigurationId().equalsIgnoreCase(credentialConfigurationId))
                .map(DispatchRule::format)
                .findFirst()
                .orElseThrow(() -> new UnknownCredentialFormatException(
                        "Unknown credential configuration id for dispatch: " + credentialConfigurationId));
    }

    private DispatchReason resolveReason(CredentialFormat formatFromType, CredentialFormat formatFromContext) {
        if (formatFromContext == null) {
            return DispatchReason.BY_TYPE;
        }
        if (formatFromType != formatFromContext) {
            return DispatchReason.BY_TYPE_CONTEXT_MISMATCH;
        }
        return DispatchReason.BY_TYPE;
    }

    private CredentialFormat resolveFormatFromContext(JsonNode credential) {
        JsonNode contextNode = credential.get("@context");
        if (contextNode == null || contextNode.isNull()) {
            return null;
        }

        if (contextNode.isTextual()) {
            return mapContextValue(contextNode.asText());
        }

        if (contextNode.isArray()) {
            for (JsonNode entry : contextNode) {
                if (entry != null && entry.isTextual()) {
                    CredentialFormat format = mapContextValue(entry.asText());
                    if (format != null) {
                        return format;
                    }
                }
            }
        }

        return null;
    }

    private CredentialFormat mapContextValue(String contextValue) {
        if (contextValue == null) {
            return null;
        }
        String normalized = contextValue.trim().toLowerCase(Locale.ROOT);
        if (VC_V2_CONTEXT.equals(normalized)) {
            return CredentialFormat.BUMPED_V2_0;
        }
        if (VC_V1_CONTEXT.equals(normalized)) {
            return CredentialFormat.LEGACY_V1_1;
        }
        return null;
    }

    private String resolveTenantDomain() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes == null) {
                return "default";
            }
            HttpServletRequest request = attributes.getRequest();
            String tenantDomain = TenantDomainFilter.getCurrentTenant(request);
            return tenantDomain == null || tenantDomain.isBlank() ? "default" : tenantDomain;
        } catch (Exception ex) {
            log.debug("Unable to resolve tenant domain from request context. Falling back to default", ex);
            return "default";
        }
    }
}
