package es.in2.vcverifier.oauth2.domain.model;

import es.in2.vcverifier.shared.domain.model.AssuranceLevel;

import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

public record RequestedAssuranceLevel(AssuranceLevel level, boolean essential) {

    private static final String ID_TOKEN = "id_token";
    private static final String ACR = "acr";
    private static final String ESSENTIAL = "essential";
    private static final String VALUE = "value";
    private static final String VALUES = "values";

    public RequestedAssuranceLevel {
        Objects.requireNonNull(level, "level");
    }

    public static Optional<RequestedAssuranceLevel> from(String acrValues, Map<String, Object> claims) {
        Optional<RequestedAssuranceLevel> fromClaims = fromClaims(claims);
        if (fromClaims.isPresent()) {
            return fromClaims;
        }
        return lowestLevel(acrValues == null ? Stream.empty() : Arrays.stream(acrValues.trim().split("\\s+")))
                .map(level -> new RequestedAssuranceLevel(level, false));
    }

    private static Optional<RequestedAssuranceLevel> fromClaims(Map<String, Object> claims) {
        if (claims == null || claims.get(ID_TOKEN) == null) {
            return Optional.empty();
        }
        if (!(claims.get(ID_TOKEN) instanceof Map<?, ?> idToken)) {
            throw new IllegalArgumentException("claims.id_token must be an object");
        }
        Object acr = idToken.get(ACR);
        if (acr == null) {
            return Optional.empty();
        }
        if (!(acr instanceof Map<?, ?> acrRequest)) {
            throw new IllegalArgumentException("claims.id_token.acr must be an object or null");
        }
        boolean essential = essential(acrRequest.get(ESSENTIAL));
        return lowestLevel(Stream.concat(singleValue(acrRequest.get(VALUE)), multipleValues(acrRequest.get(VALUES))))
                .map(level -> new RequestedAssuranceLevel(level, essential));
    }

    private static boolean essential(Object essential) {
        if (essential == null) {
            return false;
        }
        if (!(essential instanceof Boolean value)) {
            throw new IllegalArgumentException("claims.id_token.acr.essential must be a boolean");
        }
        return value;
    }

    private static Stream<String> singleValue(Object value) {
        if (value == null) {
            return Stream.empty();
        }
        if (!(value instanceof String text)) {
            throw new IllegalArgumentException("claims.id_token.acr.value must be a string");
        }
        return Stream.of(text);
    }

    private static Stream<String> multipleValues(Object values) {
        if (values == null) {
            return Stream.empty();
        }
        if (!(values instanceof Collection<?> list) || !list.stream().allMatch(String.class::isInstance)) {
            throw new IllegalArgumentException("claims.id_token.acr.values must be an array of strings");
        }
        return list.stream().map(String.class::cast);
    }

    private static Optional<AssuranceLevel> lowestLevel(Stream<String> acrValues) {
        return acrValues
                .map(AssuranceLevel::fromAcrValue)
                .flatMap(Optional::stream)
                .min(Comparator.naturalOrder());
    }
}
