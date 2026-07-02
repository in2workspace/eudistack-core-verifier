package es.in2.vcverifier.oauth2.domain.model;

import lombok.Builder;

import java.util.List;

@Builder
public record DerivedClientCredentials(
        String clientId,
        List<String> scopes,
        String grantType,
        String tenant
) {
}
