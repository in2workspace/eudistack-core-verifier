package es.in2.vcverifier.verifier.domain.model.dcql;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record DcqlQuery(
        @JsonProperty("credentials") List<CredentialQuery> credentials
) {

    /**
     * Top-level claims this query asks for within the credential queries that accept the given vct.
     * Empty when no query matches or none names specific claims.
     * <p>
     * Known limitation (technical debt): a credential query without {@code claims} yields an empty set, which
     * the schema validation reads as "enforce every mandatory attribute". OID4VP 1.0 §6.4.1 states that such a
     * query requests no selectively disclosable attribute, so a wallet that applies selective disclosure
     * would send none of them and the presentation would be rejected. It has no effect today because our
     * wallet sends every disclosure. The fix, to be done before or together with selective disclosure in the
     * wallet, is to require no selectively disclosable attribute when the query lists no claims.
     */
    public Set<String> requestedTopLevelClaims(String vct) {
        return credentials.stream()
                .filter(query -> query.meta() != null && query.meta().vctValues() != null
                        && query.meta().vctValues().contains(vct))
                .filter(query -> query.claims() != null)
                .flatMap(query -> query.claims().stream())
                .filter(claim -> claim.path() != null && !claim.path().isEmpty())
                .map(claim -> claim.path().get(0))
                .collect(Collectors.toSet());
    }
}
