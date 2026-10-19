package es.in2.vcverifier.oauth2.domain.model;

import lombok.Builder;

@Builder(toBuilder = true)
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
         * parámetro está ausente o supera la TTL máxima de sesión; un valor malformado se
         * rechaza antes con {@code invalid_request}.
         */
        Long maxAge,
        /**
         * {@code access_profile} of the request: names a named restriction applied on top of the
         * scope's DCQL query (e.g. {@code issuer_access}). {@code null} when absent.
         */
        String accessProfile,
        /**
         * Issuer the discovery document advertises for the host of this {@code /oidc/authorize}
         * request; sent as {@code iss} in every authorization response (RFC 9207).
         */
        String issuer
) {
}
