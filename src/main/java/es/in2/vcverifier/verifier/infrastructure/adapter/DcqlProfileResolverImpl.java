package es.in2.vcverifier.verifier.infrastructure.adapter;

import es.in2.vcverifier.verifier.domain.exception.InvalidScopeException;
import es.in2.vcverifier.verifier.domain.model.dcql.CredentialQuery;
import es.in2.vcverifier.verifier.domain.model.dcql.DcqlQuery;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import es.in2.vcverifier.verifier.infrastructure.config.DcqlProfileProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Resolves OIDC scopes to DCQL queries using pre-configured profiles from application YAML.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DcqlProfileResolverImpl implements DcqlProfileResolver {

    private static final Set<String> OIDC_STANDARD_SCOPES = Set.of(
            "openid", "profile", "email", "offline_access", "role", "address", "phone"
    );

    private final DcqlProfileProperties dcqlProfileProperties;

    @Override
    public DcqlQuery resolve(String scopeString) {
        if (scopeString == null || scopeString.isBlank()) {
            throw new InvalidScopeException("Scope string is empty");
        }

        List<String> oid4vpScopes = Arrays.stream(scopeString.trim().split("\\s+"))
                .filter(s -> !OIDC_STANDARD_SCOPES.contains(s))
                .toList();

        if (oid4vpScopes.isEmpty()) {
            throw new InvalidScopeException(
                    "No OID4VP scope found. At least one scope must map to a DCQL profile. " +
                    "Available profiles: " + dcqlProfileProperties.profiles().keySet());
        }

        List<CredentialQuery> mergedCredentials = new ArrayList<>();

        for (String scope : oid4vpScopes) {
            DcqlProfileProperties.DcqlProfile profile = dcqlProfileProperties.profiles().get(scope);
            if (profile == null) {
                throw new InvalidScopeException(
                        "No DCQL profile configured for scope '" + scope + "'. " +
                        "Available profiles: " + dcqlProfileProperties.profiles().keySet());
            }
            for (DcqlProfileProperties.CredentialEntry entry : profile.credentials()) {
                mergedCredentials.add(toCredentialQuery(entry));
            }
        }

        log.info("Resolved {} scope(s) {} into DCQL query with {} credential queries",
                oid4vpScopes.size(), oid4vpScopes, mergedCredentials.size());

        return new DcqlQuery(mergedCredentials);
    }

    private CredentialQuery toCredentialQuery(DcqlProfileProperties.CredentialEntry entry) {
        CredentialQuery.CredentialMeta meta = null;
        if (entry.meta() != null) {
            CredentialQuery.CredentialDefinition credDef = null;
            if (entry.meta().credentialDefinition() != null) {
                credDef = new CredentialQuery.CredentialDefinition(entry.meta().credentialDefinition().type());
            }
            meta = new CredentialQuery.CredentialMeta(entry.meta().vctValues(), credDef);
        }
        return new CredentialQuery(entry.id(), entry.format(), meta, null);
    }
}
