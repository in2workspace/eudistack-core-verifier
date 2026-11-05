package es.in2.vcverifier.verifier.domain.model;

import es.in2.vcverifier.shared.domain.model.AssuranceLevel;

import java.util.List;
import java.util.Objects;

public sealed interface CertificateTrust {

    record Trusted(AssuranceLevel level, List<String> amr) implements CertificateTrust {

        public Trusted {
            Objects.requireNonNull(level, "level");
            amr = List.copyOf(amr);
        }
    }

    record Rejected(CertificateLoginReason reason) implements CertificateTrust {

        public Rejected {
            Objects.requireNonNull(reason, "reason");
        }
    }
}
