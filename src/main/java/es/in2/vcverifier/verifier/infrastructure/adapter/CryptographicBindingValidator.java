package es.in2.vcverifier.verifier.infrastructure.adapter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.crypto.DIDService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.exception.InvalidScopeException;
import es.in2.vcverifier.verifier.domain.exception.InvalidVPtokenException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Map;

/**
 * Validates VP signature (PoP) and cryptographic binding between VP holder and VC subject
 * via cnf.jwk thumbprint comparison (RFC 7638).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CryptographicBindingValidator {

    private final JWTService jwtService;
    private final DIDService didService;

    /**
     * Verifies the VP signature and returns the signer's EC public key.
     * Tries embedded JWK first; falls back to DID resolution from kid/iss/sub.
     *
     * @param verifiablePresentation the raw VP JWT string
     * @param vpJwt                  the parsed VP JWT
     * @return the EC public key of the VP signer
     */
    public ECPublicKey validateVpSignature(String verifiablePresentation, SignedJWT vpJwt) {
        // Strategy 1: Embedded JWK in VP header
        ECKey vpHeaderJwk = extractJwkFromHeader(vpJwt);
        if (vpHeaderJwk != null) {
            log.info("[BIND] VP signed with embedded JWK (kid={})", vpHeaderJwk.getKeyID());
            ECPublicKey signerKey;
            try {
                signerKey = vpHeaderJwk.toECPublicKey();
            } catch (JOSEException e) {
                throw new InvalidVPtokenException("Cannot extract EC public key from VP header JWK");
            }
            jwtService.verifyJWTWithECKey(verifiablePresentation, signerKey);
            log.info("VP signature verified via embedded JWK");
            return signerKey;
        }

        // Strategy 2: Legacy DID resolution from kid/iss/sub
        String vpKid = vpJwt.getHeader().getKeyID();
        String vpIss;
        String vpSub;
        try {
            var claims = vpJwt.getJWTClaimsSet();
            vpIss = claims.getIssuer();
            vpSub = claims.getSubject();
        } catch (Exception e) {
            throw new InvalidVPtokenException("Cannot read vp_token claims");
        }

        String holderDid = normalizeDid(extractDidFromKidIssSub(vpKid, vpIss, vpSub));
        if (holderDid == null || holderDid.isBlank()) {
            throw new InvalidScopeException("Cannot extract holder identity from VP (no jwk header and no DID in kid/iss/sub)");
        }

        log.info("[BIND] VP holder DID resolved as {}", holderDid);
        PublicKey holderPublicKey = didService.resolvePublicKeyFromDid(holderDid);

        if (!(holderPublicKey instanceof ECPublicKey ecPub)) {
            throw new InvalidVPtokenException("Resolved DID public key is not an EC public key");
        }

        jwtService.verifyJWTWithECKey(verifiablePresentation, ecPub);
        log.info("VP signature verified via DID resolution (legacy)");

        return ecPub;
    }

    /**
     * Validates cryptographic binding between the VP signer and the VC holder via a priority chain:
     * 1. cnf.jwk (RFC 7800 embedded JWK) — direct thumbprint comparison
     * 2. cnf.kid (key ID as DID URL) — resolve via DIDService, then thumbprint comparison
     * 3. credentialSubject.mandate.mandatee.id (did:key fallback) — resolve via DIDService
     *
     * @param vpSignerKey   the EC public key of the VP signer
     * @param jwtCredential the parsed VC JWT
     */
    public void validateCryptographicBinding(ECPublicKey vpSignerKey, SignedJWT jwtCredential) {
        if (vpSignerKey == null) {
            throw new InvalidScopeException("Cannot extract VP signer key — cannot validate cryptographic binding");
        }

        // Strategy 1: cnf.jwk
        ECKey cnfJwk = extractCnfJwkFromVc(jwtCredential);
        if (cnfJwk != null) {
            log.info("[BIND] Validating binding via cnf.jwk");
            validateBindingByJwkThumbprint(vpSignerKey, cnfJwk);
            return;
        }

        // Strategy 2: cnf.kid (DID URL)
        String cnfKid = extractCnfKidFromVc(jwtCredential);
        if (cnfKid != null) {
            log.info("[BIND] Validating binding via cnf.kid: {}", cnfKid);
            ECKey resolved = resolveEcKeyFromDid(normalizeDid(cnfKid));
            validateBindingByJwkThumbprint(vpSignerKey, resolved);
            return;
        }

        // Strategy 3: mandatee.id fallback
        String mandateeId = extractMandateeIdFromVc(jwtCredential);
        if (mandateeId != null && mandateeId.startsWith("did:")) {
            log.info("[BIND] Validating binding via mandatee.id fallback: {}", mandateeId);
            ECKey resolved = resolveEcKeyFromDid(normalizeDid(mandateeId));
            validateBindingByJwkThumbprint(vpSignerKey, resolved);
            return;
        }

        throw new InvalidScopeException(
                "Credential missing cnf.jwk / cnf.kid / mandatee.id — cannot validate cryptographic binding");
    }

    String normalizeDid(String did) {
        if (did == null) return null;
        if (!did.startsWith("did:")) return did;
        return did.contains("#") ? did.substring(0, did.indexOf('#')) : did;
    }

    private ECKey extractJwkFromHeader(SignedJWT signedJwt) {
        var jwk = signedJwt.getHeader().getJWK();
        if (jwk instanceof ECKey ecKey) {
            return ecKey;
        }
        return null;
    }

    private String extractDidFromKidIssSub(String kid, String iss, String sub) {
        if (kid != null && kid.startsWith("did:")) {
            return kid.contains("#") ? kid.substring(0, kid.indexOf('#')) : kid;
        }
        if (iss != null && iss.startsWith("did:")) return iss;
        if (sub != null && sub.startsWith("did:")) return sub;
        return null;
    }

    @SuppressWarnings("unchecked")
    private ECKey extractCnfJwkFromVc(SignedJWT vcJwt) {
        try {
            Map<String, Object> cnf = (Map<String, Object>) vcJwt.getJWTClaimsSet().getClaim("cnf");
            if (cnf == null) return null;

            Map<String, Object> jwk = (Map<String, Object>) cnf.get("jwk");
            if (jwk == null) return null;

            return ECKey.parse(jwk);
        } catch (Exception e) {
            log.warn("Failed to extract cnf.jwk from VC: {}", e.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private String extractCnfKidFromVc(SignedJWT vcJwt) {
        try {
            Map<String, Object> cnf = (Map<String, Object>) vcJwt.getJWTClaimsSet().getClaim("cnf");
            if (cnf == null) return null;
            Object kid = cnf.get("kid");
            return kid instanceof String s ? s : null;
        } catch (Exception e) {
            log.warn("Failed to extract cnf.kid from VC: {}", e.getMessage());
            return null;
        }
    }

    private String extractMandateeIdFromVc(SignedJWT vcJwt) {
        try {
            var claims = vcJwt.getJWTClaimsSet();

            // W3C format: credentialSubject.mandate.mandatee.id
            Object cs = claims.getClaim("credentialSubject");
            if (cs instanceof Map<?, ?> csMap) {
                Object mandate = csMap.get("mandate");
                if (mandate instanceof Map<?, ?> mandateMap) {
                    Object mandatee = mandateMap.get("mandatee");
                    if (mandatee instanceof Map<?, ?> mandateeMap) {
                        Object id = mandateeMap.get("id");
                        if (id instanceof String s) return s;
                    }
                }
            }

            // SD-JWT flat format: mandate.mandatee.id (top-level)
            Object mandate = claims.getClaim("mandate");
            if (mandate instanceof Map<?, ?> mandateMap) {
                Object mandatee = mandateMap.get("mandatee");
                if (mandatee instanceof Map<?, ?> mandateeMap) {
                    Object id = mandateeMap.get("id");
                    if (id instanceof String s) return s;
                }
            }

            return null;
        } catch (Exception e) {
            log.warn("Failed to extract mandatee.id from VC: {}", e.getMessage());
            return null;
        }
    }

    private ECKey resolveEcKeyFromDid(String did) {
        PublicKey resolved = didService.resolvePublicKeyFromDid(did);
        if (!(resolved instanceof ECPublicKey ecPub)) {
            throw new InvalidScopeException("Resolved DID key is not EC — cannot validate cryptographic binding: " + did);
        }
        try {
            return new ECKey.Builder(Curve.P_256, ecPub).build();
        } catch (Exception e) {
            throw new InvalidScopeException("Failed to wrap resolved EC key: " + e.getMessage());
        }
    }

    private void validateBindingByJwkThumbprint(ECPublicKey vpSignerKey, ECKey vcCnfJwk) {
        try {
            ECKey vpSignerEcKey = new ECKey.Builder(Curve.P_256, vpSignerKey).build();
            String vpThumbprint = vpSignerEcKey.computeThumbprint().toString();
            String vcThumbprint = vcCnfJwk.computeThumbprint().toString();

            log.debug("[BIND] VP signer thumbprint: {}", vpThumbprint);
            log.debug("[BIND] VC cnf.jwk thumbprint: {}", vcThumbprint);

            if (!vpThumbprint.equals(vcThumbprint)) {
                throw new InvalidScopeException(
                        "Cryptographic binding mismatch: VP signer JWK Thumbprint (" + vpThumbprint +
                        ") != VC cnf.jwk Thumbprint (" + vcThumbprint + ")"
                );
            }
            log.info("Cryptographic binding validated via JWK Thumbprint (RFC 7638)");
        } catch (InvalidScopeException e) {
            throw e;
        } catch (JOSEException e) {
            throw new InvalidScopeException("Failed to compute JWK Thumbprint for binding validation: " + e.getMessage());
        }
    }

}
