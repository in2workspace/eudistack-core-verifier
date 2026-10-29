package es.in2.vcverifier.shared.infrastructure.audit;

import com.eudistack.auditoria.port.AuditAccessTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;

/**
 * Interim access token of the Verifier for the Audit API, read from {@code AUDIT_API_ACCESS_TOKEN}. It lets the
 * dispatcher run against a local Audit API (its {@code devTokens}). The token a deployed Verifier needs, with
 * the power {@code organization · EUDISTACK · Audit · Write}, has to be obtained with the system credentials
 * it uses against itself; that is not built yet.
 */
@Component
@ConditionalOnBooleanProperty("auditoria.dispatcher.enabled")
public class ConfiguredAuditAccessTokenProvider implements AuditAccessTokenProvider {

    private final String accessToken;

    public ConfiguredAuditAccessTokenProvider(@Value("${AUDIT_API_ACCESS_TOKEN:}") String accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public String accessToken(@Nullable String audience) {
        if (accessToken.isBlank()) {
            throw new IllegalStateException("AUDIT_API_ACCESS_TOKEN is not set");
        }
        return accessToken;
    }

    @Override
    public String refreshAccessToken(@Nullable String audience) {
        return accessToken(audience);
    }
}
