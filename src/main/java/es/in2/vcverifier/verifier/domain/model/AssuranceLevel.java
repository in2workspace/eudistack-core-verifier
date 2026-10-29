package es.in2.vcverifier.verifier.domain.model;

public enum AssuranceLevel {

    SUBSTANTIAL("http://eidas.europa.eu/LoA/substantial"),
    HIGH("http://eidas.europa.eu/LoA/high");

    private final String acrValue;

    AssuranceLevel(String acrValue) {
        this.acrValue = acrValue;
    }

    public String acrValue() {
        return acrValue;
    }

    public boolean satisfies(AssuranceLevel required) {
        return compareTo(required) >= 0;
    }
}
