package es.in2.vcverifier.oauth2.domain.model;

import lombok.Builder;

@Builder
public record AuthorizationContext(
        String state,
        String scope,
        String redirectUri,
        String clientNonce,
        String originalRequestURL,
        String requestUri,
        String codeChallenge,
        String codeChallengeMethod,
        String portalUrl,
        String contextPath,
        /**
         * FR-21/AC-09: {@code max_age} del request OIDC, en segundos. {@code null} si el
         * parámetro está ausente o no es un entero no negativo válido.
         */
        Long maxAge
) {
}
