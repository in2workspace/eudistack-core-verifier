package es.in2.vcverifier.oauth2.domain.model;

import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequestedAssuranceLevelTest {

    private static final String SUBSTANTIAL = "http://eidas.europa.eu/LoA/substantial";
    private static final String HIGH = "http://eidas.europa.eu/LoA/high";

    @Test
    void from_withoutAcrValuesNorClaims_requestsNoLevel() {
        assertThat(RequestedAssuranceLevel.from(null, null)).isEmpty();
    }

    @Test
    void from_acrValues_isAPreference() {
        assertThat(RequestedAssuranceLevel.from(HIGH, null))
                .contains(new RequestedAssuranceLevel(AssuranceLevel.HIGH, false));
    }

    @Test
    void from_acrValuesWithSeveralLevels_requestsTheLowestAcceptedOne() {
        assertThat(RequestedAssuranceLevel.from(HIGH + " " + SUBSTANTIAL, null))
                .contains(new RequestedAssuranceLevel(AssuranceLevel.SUBSTANTIAL, false));
    }

    @Test
    void from_acrValuesWithOnlyUnknownValues_requestsNoLevel() {
        assertThat(RequestedAssuranceLevel.from("urn:example:loa:4 1", null)).isEmpty();
    }

    @Test
    void from_acrValuesWithUnknownValues_ignoresThem() {
        assertThat(RequestedAssuranceLevel.from("urn:example:loa:4 " + HIGH, null))
                .contains(new RequestedAssuranceLevel(AssuranceLevel.HIGH, false));
    }

    @Test
    void from_essentialClaim_isEssential() {
        assertThat(RequestedAssuranceLevel.from(null, acrClaim(Map.of("essential", true, "values", List.of(HIGH)))))
                .contains(new RequestedAssuranceLevel(AssuranceLevel.HIGH, true));
    }

    @Test
    void from_claimWithoutEssential_isAPreference() {
        assertThat(RequestedAssuranceLevel.from(null, acrClaim(Map.of("value", SUBSTANTIAL))))
                .contains(new RequestedAssuranceLevel(AssuranceLevel.SUBSTANTIAL, false));
    }

    @Test
    void from_claimWithValueAndValues_requestsTheLowestOfAll() {
        assertThat(RequestedAssuranceLevel.from(null,
                acrClaim(Map.of("essential", true, "value", HIGH, "values", List.of(SUBSTANTIAL)))))
                .contains(new RequestedAssuranceLevel(AssuranceLevel.SUBSTANTIAL, true));
    }

    @Test
    void from_claim_winsOverAcrValues() {
        assertThat(RequestedAssuranceLevel.from(SUBSTANTIAL, acrClaim(Map.of("essential", true, "value", HIGH))))
                .contains(new RequestedAssuranceLevel(AssuranceLevel.HIGH, true));
    }

    @Test
    void from_claimWithoutKnownLevel_fallsBackToAcrValues() {
        assertThat(RequestedAssuranceLevel.from(SUBSTANTIAL, acrClaim(Map.of("essential", true, "value", "urn:x"))))
                .contains(new RequestedAssuranceLevel(AssuranceLevel.SUBSTANTIAL, false));
    }

    @Test
    void from_claimsWithoutAcr_fallsBackToAcrValues() {
        Map<String, Object> claims = Map.of("id_token", Map.of("email", Map.of("essential", true)));

        assertThat(RequestedAssuranceLevel.from(HIGH, claims))
                .contains(new RequestedAssuranceLevel(AssuranceLevel.HIGH, false));
    }

    @Test
    void from_acrClaimRequestedWithNull_requestsNoLevel() {
        Map<String, Object> idToken = new HashMap<>();
        idToken.put("acr", null);

        assertThat(RequestedAssuranceLevel.from(null, Map.of("id_token", idToken))).isEmpty();
    }

    @Test
    void from_claimsForUserinfoOnly_requestsNoLevel() {
        assertThat(RequestedAssuranceLevel.from(null, Map.of("userinfo", Map.of("acr", Map.of("value", HIGH)))))
                .isEmpty();
    }

    @Test
    void from_idTokenNotAnObject_isInvalid() {
        assertThatThrownBy(() -> RequestedAssuranceLevel.from(null, Map.of("id_token", "acr")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void from_acrNotAnObject_isInvalid() {
        assertThatThrownBy(() -> RequestedAssuranceLevel.from(null, Map.of("id_token", Map.of("acr", HIGH))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void from_essentialNotABoolean_isInvalid() {
        assertThatThrownBy(() -> RequestedAssuranceLevel.from(null,
                acrClaim(Map.of("essential", "true", "value", HIGH))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void from_valueNotAString_isInvalid() {
        assertThatThrownBy(() -> RequestedAssuranceLevel.from(null, acrClaim(Map.of("value", List.of(HIGH)))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void from_valuesNotAnArrayOfStrings_isInvalid() {
        assertThatThrownBy(() -> RequestedAssuranceLevel.from(null, acrClaim(Map.of("values", HIGH))))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RequestedAssuranceLevel.from(null, acrClaim(Map.of("values", List.of(1)))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static Map<String, Object> acrClaim(Map<String, Object> acr) {
        return Map.of("id_token", Map.of("acr", acr));
    }
}
