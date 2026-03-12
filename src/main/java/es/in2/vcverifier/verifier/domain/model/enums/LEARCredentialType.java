package es.in2.vcverifier.verifier.domain.model.enums;

import lombok.Getter;

@Getter
public enum LEARCredentialType {

    LEAR_CREDENTIAL_EMPLOYEE("learcredential.employee.w3c.4"),
    LEAR_CREDENTIAL_MACHINE("learcredential.machine.w3c.3");

    private final String value;

    LEARCredentialType(String value) {
        this.value = value;
    }

}
