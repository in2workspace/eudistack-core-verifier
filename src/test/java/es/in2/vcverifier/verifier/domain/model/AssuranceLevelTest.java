package es.in2.vcverifier.verifier.domain.model;

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
}
