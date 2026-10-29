package es.in2.vcverifier.shared.domain.model;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LoginMethodTest {

    @Test
    void fromValues_withoutValues_defaultsToWallet() {
        assertThat(LoginMethod.fromValues(null)).containsExactly(LoginMethod.WALLET);
    }

    @Test
    void fromValues_withEmptyList_defaultsToWallet() {
        assertThat(LoginMethod.fromValues(List.of())).containsExactly(LoginMethod.WALLET);
    }

    @Test
    void fromValues_keepsTheOrderOfTheRegistration() {
        assertThat(LoginMethod.fromValues(List.of("x509", "wallet")))
                .containsExactly(LoginMethod.X509, LoginMethod.WALLET);
    }

    @Test
    void fromValues_dropsRepeatedValues() {
        assertThat(LoginMethod.fromValues(List.of("wallet", "x509", "wallet")))
                .containsExactly(LoginMethod.WALLET, LoginMethod.X509);
    }

    @Test
    void fromValues_withUnknownValue_namesIt() {
        assertThatThrownBy(() -> LoginMethod.fromValues(List.of("x509", "clave")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'clave'");
    }

    @Test
    void fromValue_isCaseSensitive() {
        assertThatThrownBy(() -> LoginMethod.fromValue("X509"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void value_isTheRegistrationValue() {
        assertThat(LoginMethod.WALLET.value()).isEqualTo("wallet");
        assertThat(LoginMethod.X509.value()).isEqualTo("x509");
    }
}
