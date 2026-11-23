package es.in2.vcverifier.verifier.domain.model;

import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.exception.TrustListUnavailableException;

import java.util.Objects;

public sealed interface IssuerTrust {

    record Trusted(String entityIdentifier, String serviceType, String listUrl, String listType,
                   Integer listSequenceNumber) implements IssuerTrust {

        public Trusted {
            Objects.requireNonNull(entityIdentifier, "entityIdentifier");
            Objects.requireNonNull(serviceType, "serviceType");
        }
    }

    record NotTrusted(String reason) implements IssuerTrust {
    }

    record Unavailable(String reason) implements IssuerTrust {
    }

    default Trusted orThrow() {
        return switch (this) {
            case Trusted trusted -> trusted;
            case NotTrusted(String reason) -> throw new IssuerNotAuthorizedException(reason);
            case Unavailable(String reason) -> throw new TrustListUnavailableException(reason);
        };
    }
}
