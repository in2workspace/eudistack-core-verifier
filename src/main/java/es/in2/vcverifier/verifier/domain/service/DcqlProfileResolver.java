package es.in2.vcverifier.verifier.domain.service;

import es.in2.vcverifier.verifier.domain.model.dcql.DcqlQuery;

/**
 * Resolves OIDC scopes from Relying Parties into DCQL queries for wallets.
 * <p>
 * Standard OIDC scopes (openid, profile, email, offline_access, role) are filtered out.
 * The remaining scopes are matched against pre-configured DCQL profiles and their
 * credential queries are merged into a single DcqlQuery.
 */
public interface DcqlProfileResolver {

    /**
     * Resolves a space-separated scope string into a DCQL query.
     *
     * @param scopeString the OIDC scope string (e.g. "openid learcredential.employee")
     * @return the merged DCQL query for all matched scope profiles
     * @throws es.in2.vcverifier.verifier.domain.exception.InvalidScopeException
     *         if no scope maps to a DCQL profile
     */
    DcqlQuery resolve(String scopeString);
}
