package es.in2.vcverifier.oauth2.domain.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OidcPromptTest {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "consent", "select_account consent"})
    void parse_absentOrUnsupportedValues_allowsReuse(String raw) {
        // When
        OidcPrompt prompt = OidcPrompt.parse(raw);

        // Then
        assertFalse(prompt.isNone());
        assertFalse(prompt.requiresLogin());
        assertFalse(prompt.isInvalidNoneCombination());
    }

    @Test
    void parse_none_isNone() {
        OidcPrompt prompt = OidcPrompt.parse("none");

        assertTrue(prompt.isNone());
        assertFalse(prompt.isInvalidNoneCombination());
    }

    @ParameterizedTest
    @ValueSource(strings = {"login", "consent login", " login  select_account "})
    void parse_containingLogin_requiresLogin(String raw) {
        assertTrue(OidcPrompt.parse(raw).requiresLogin());
    }

    @ParameterizedTest
    @ValueSource(strings = {"none login", "consent none", "none  select_account"})
    void parse_noneWithAnotherValue_isInvalidAndNotNone(String raw) {
        OidcPrompt prompt = OidcPrompt.parse(raw);

        assertTrue(prompt.isInvalidNoneCombination());
        assertFalse(prompt.isNone());
    }

    @Test
    void parse_valuesAreCaseSensitive() {
        // OIDC Core §3.1.2.1: values are case-sensitive, "NONE" is not "none"
        OidcPrompt prompt = OidcPrompt.parse("NONE");

        assertFalse(prompt.isNone());
        assertEquals(1, prompt.values().size());
    }
}
