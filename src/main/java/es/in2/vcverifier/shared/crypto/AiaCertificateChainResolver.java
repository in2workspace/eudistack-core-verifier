package es.in2.vcverifier.shared.crypto;

import java.security.cert.X509Certificate;
import java.util.List;

public interface AiaCertificateChainResolver {

    /**
     * Given a leaf-first x5c chain (possibly just the leaf), returns the chain extended
     * via AIA {@code caIssuers} fetching until a self-signed root is reached, no
     * {@code caIssuers} URL is present, or a depth guard fires.
     *
     * <p>Returns the input unchanged when chasing is disabled by config, when the
     * chain is null/empty, or when the top cert is already self-signed.
     *
     * <p>Note: this method accepts any self-signed root reached via AIA — there is
     * no trust-anchor pinning. A warning is logged for roots that were not present
     * in the original x5c input. A configurable trust store is on the roadmap.
     */
    List<X509Certificate> completeChain(List<X509Certificate> x5cChain);
}
