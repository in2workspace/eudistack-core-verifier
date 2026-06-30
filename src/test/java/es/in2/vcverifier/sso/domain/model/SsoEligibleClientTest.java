package es.in2.vcverifier.sso.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SsoEligibleClientTest {

    // =========================================================
    // of() — normalización trim
    // =========================================================

    @Test
    void of_trimsLeadingAndTrailingWhitespace() {
        SsoEligibleClient client = SsoEligibleClient.of("  my-client  ");

        assertThat(client.clientId()).isEqualTo("my-client");
    }

    @Test
    void of_trimsOnlyBoundaryWhitespace_leavingInternalSpacesIntact() {
        SsoEligibleClient client = SsoEligibleClient.of("  my client  ");

        assertThat(client.clientId()).isEqualTo("my client");
    }

    @Test
    void of_doesNotTransformCase() {
        SsoEligibleClient client = SsoEligibleClient.of("ClientID-123");

        assertThat(client.clientId()).isEqualTo("ClientID-123");
    }

    @Test
    void of_alreadyTrimmedValue_isStoredUnchanged() {
        SsoEligibleClient client = SsoEligibleClient.of("client-x");

        assertThat(client.clientId()).isEqualTo("client-x");
    }

    // =========================================================
    // of() — rechazo vacío
    // =========================================================

    @Test
    void of_throwsNullPointerException_whenClientIdIsNull() {
        assertThatThrownBy(() -> SsoEligibleClient.of(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void of_throwsIllegalArgumentException_whenClientIdIsEmpty() {
        assertThatThrownBy(() -> SsoEligibleClient.of(""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void of_throwsIllegalArgumentException_whenClientIdIsWhitespaceOnly() {
        assertThatThrownBy(() -> SsoEligibleClient.of("   "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // =========================================================
    // equals / hashCode
    // =========================================================

    @Test
    void equals_returnsTrue_whenClientIdsMatchAfterNormalization() {
        SsoEligibleClient a = SsoEligibleClient.of("  client-x  ");
        SsoEligibleClient b = SsoEligibleClient.of("client-x");

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    void equals_returnsFalse_whenClientIdsDiffer() {
        SsoEligibleClient a = SsoEligibleClient.of("client-x");
        SsoEligibleClient b = SsoEligibleClient.of("client-y");

        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void equals_returnsTrue_forSameInstance() {
        SsoEligibleClient client = SsoEligibleClient.of("client-x");

        assertThat(client).isEqualTo(client);
    }

    // =========================================================
    // toString
    // =========================================================

    @Test
    void toString_containsNormalizedClientId() {
        SsoEligibleClient client = SsoEligibleClient.of("  client-x  ");

        assertThat(client.toString()).contains("client-x");
    }
}
