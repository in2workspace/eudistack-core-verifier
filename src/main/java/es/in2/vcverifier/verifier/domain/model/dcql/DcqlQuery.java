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
