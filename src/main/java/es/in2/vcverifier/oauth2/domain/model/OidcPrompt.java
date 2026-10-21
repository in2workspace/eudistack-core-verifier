package es.in2.vcverifier.oauth2.domain.model;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * OIDC Core 1.0 §3.1.2.1 {@code prompt}: space-delimited, case-sensitive list of values.
 *
 * <p>Only {@code none} and {@code login} change the Verifier's behaviour. Any other value
 * ({@code consent}, {@code select_account}, unknown extensions) is not supported and is treated
 * as if it were absent: the OP may reuse an existing session.
 */
public record OidcPrompt(Set<String> values) {

    private static final String NONE = "none";
    private static final String LOGIN = "login";

    public OidcPrompt {
        values = values == null ? Set.of() : Set.copyOf(values);
    }

    public static OidcPrompt parse(String rawPrompt) {
        if (rawPrompt == null || rawPrompt.isBlank()) {
            return new OidcPrompt(Set.of());
        }
        return new OidcPrompt(Arrays.stream(rawPrompt.trim().split("\\s+"))
                .filter(value -> !value.isBlank())
                .collect(Collectors.toSet()));
    }

    /** {@code none} must be the only value — combined with any other one the request is invalid. */
    public boolean isInvalidNoneCombination() {
        return values.contains(NONE) && values.size() > 1;
    }

    /** {@code prompt=none}: no UI at all; if the session cannot be reused, an OIDC error goes back to the client. */
    public boolean isNone() {
        return values.contains(NONE) && values.size() == 1;
    }

    /** {@code prompt=login}: the user must re-authenticate, an existing session is never reused. */
    public boolean requiresLogin() {
        return values.contains(LOGIN);
    }
}
