package es.in2.vcverifier.shared.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AssuranceLevelTest {

    @Test
    void acrValue_isTheEidasLevelOfAssurance() {
        assertThat(AssuranceLevel.SUBSTANTIAL.acrValue()).isEqualTo("http://eidas.europa.eu/LoA/substantial");
        assertThat(AssuranceLevel.HIGH.acrValue()).isEqualTo("http://eidas.europa.eu/LoA/high");
    }

    @Test
    void satisfies_theSameLevel() {
        assertThat(AssuranceLevel.SUBSTANTIAL.satisfies(AssuranceLevel.SUBSTANTIAL)).isTrue();
        assertThat(AssuranceLevel.HIGH.satisfies(AssuranceLevel.HIGH)).isTrue();
    }

    @Test
    void high_satisfiesSubstantial() {
        assertThat(AssuranceLevel.HIGH.satisfies(AssuranceLevel.SUBSTANTIAL)).isTrue();
    }

    @Test
    void substantial_doesNotSatisfyHigh() {
        assertThat(AssuranceLevel.SUBSTANTIAL.satisfies(AssuranceLevel.HIGH)).isFalse();
    }

    @Test
    void fromAcrValue_recognisesTheEidasLevels() {
        assertThat(AssuranceLevel.fromAcrValue("http://eidas.europa.eu/LoA/substantial")).contains(AssuranceLevel.SUBSTANTIAL);
        assertThat(AssuranceLevel.fromAcrValue("http://eidas.europa.eu/LoA/high")).contains(AssuranceLevel.HIGH);
    }

    @Test
    void fromAcrValue_ignoresOtherValues() {
        assertThat(AssuranceLevel.fromAcrValue("http://eidas.europa.eu/LoA/low")).isEmpty();
        assertThat(AssuranceLevel.fromAcrValue("high")).isEmpty();
        assertThat(AssuranceLevel.fromAcrValue(null)).isEmpty();
    }
}
