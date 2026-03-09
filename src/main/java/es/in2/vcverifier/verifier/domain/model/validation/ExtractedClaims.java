package es.in2.vcverifier.verifier.domain.model.validation;

import lombok.Builder;

import java.util.Map;

@Builder
public record ExtractedClaims(
        String subject,
        Map<String, Object> idTokenClaims,
        Map<String, Object> idTokenEmbeds,
        Map<String, Object> accessTokenClaims,
        Map<String, Object> accessTokenEmbeds,
        String scope
) {}
