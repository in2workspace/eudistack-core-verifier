package es.in2.vcverifier.verifier.domain.model.audit;

import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import static es.in2.vcverifier.shared.domain.model.audit.AuditEventType.CERTIFICATE_AUTHENTICATION;
import static es.in2.vcverifier.shared.domain.model.audit.AuditEventType.IAM_SESSION_ESTABLISHED;

public final class AuthenticationAuditEntries {

    private static final String RESOURCE_KIND = "login:";
    private static final String FINGERPRINT_ALGORITHM = "sha256:";

    private AuthenticationAuditEntries() {
    }

    public static AuditEntry of(CertificateAuthenticationAudit event) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("oidc_client_id", event.oidcClientId());
        details.put("certificate_issuer", event.certificateIssuer());
        details.put("certificate_fingerprint",
                event.certificateFingerprint() == null ? null : FINGERPRINT_ALGORITHM + event.certificateFingerprint());
        String resource = RESOURCE_KIND + event.correlationId();
        if (event.result() == AuditResult.SUCCESS) {
            details.put("assurance_level", event.assuranceLevel().name().toLowerCase(Locale.ROOT));
            details.put("amr", event.amr());
            details.put("holder", person(event.holder()));
            return AuditEntry.success(CERTIFICATE_AUTHENTICATION, resource, details);
        }
        return AuditEntry.forReason(CERTIFICATE_AUTHENTICATION, resource, event.reason().value(), details);
    }

    public static AuditEntry of(IamSessionAudit event) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("oidc_client_id", event.oidcClientId());
        details.put("session_origin", event.sessionOrigin().value());
        details.put("holder", person(event.holder()));
        String resource = RESOURCE_KIND + event.correlationId();
        if (event.result() == AuditResult.SUCCESS) {
            details.put("identity_claims", event.identityClaims());
            return AuditEntry.success(IAM_SESSION_ESTABLISHED, resource, details);
        }
        return AuditEntry.forReason(IAM_SESSION_ESTABLISHED, resource, event.reason(), details);
    }

    private static Map<String, Object> person(AuditedPerson person) {
        Map<String, Object> values = new HashMap<>();
        values.put("identifier", person.identifier());
        values.put("name", person.name());
        values.put("email", person.email());
        return values;
    }
}
