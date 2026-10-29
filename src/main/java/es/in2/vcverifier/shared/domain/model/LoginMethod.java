package es.in2.vcverifier.shared.domain.model;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public enum LoginMethod {

    WALLET("wallet"),
    X509("x509");

    private static final List<LoginMethod> DEFAULT = List.of(WALLET);

    private final String value;

    LoginMethod(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static LoginMethod fromValue(String value) {
        return Arrays.stream(values())
                .filter(method -> method.value.equals(value))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown login method '" + value + "'"));
    }

    public static List<LoginMethod> fromValues(List<String> values) {
        if (values == null || values.isEmpty()) {
            return DEFAULT;
        }
        Set<LoginMethod> methods = new LinkedHashSet<>();
        values.forEach(value -> methods.add(fromValue(value)));
        return List.copyOf(methods);
    }
}
