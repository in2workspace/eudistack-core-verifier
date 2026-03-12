package es.in2.vcverifier.verifier.domain.model;

import java.util.Arrays;
import java.util.Objects;

public record TokenStatusListData(
        String issuer,
        int bitsPerEntry,
        byte[] rawBytes
) {
    public TokenStatusListData {
        Objects.requireNonNull(rawBytes, "rawBytes cannot be null");
        if (bitsPerEntry < 1) {
            throw new IllegalArgumentException("bitsPerEntry must be >= 1, but was: " + bitsPerEntry);
        }
        rawBytes = rawBytes.clone();
    }

    @Override
    public byte[] rawBytes() {
        return rawBytes.clone();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof TokenStatusListData other)) return false;
        return bitsPerEntry == other.bitsPerEntry
                && Objects.equals(issuer, other.issuer)
                && Arrays.equals(rawBytes, other.rawBytes);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(issuer, bitsPerEntry);
        result = 31 * result + Arrays.hashCode(rawBytes);
        return result;
    }

    @Override
    public String toString() {
        return "TokenStatusListData[" +
                "issuer=" + issuer +
                ", bitsPerEntry=" + bitsPerEntry +
                ", rawBytesLength=" + rawBytes.length +
                ']';
    }
}
