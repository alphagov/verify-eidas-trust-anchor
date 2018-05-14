package uk.gov.ida.eidas.trustanchor;

import com.google.common.collect.ImmutableList;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;

class CountryTrustAnchorValidator {

    private final CertificateValidator certificateValidator;

    /**
     * @throws IllegalStateException if cannot build x509 CertificateFactory
     */
    static CountryTrustAnchorValidator build() {
        Base64X509CertificateDecoder decoder;
        try {
            decoder = new Base64X509CertificateDecoder();
        } catch (CertificateException e) {
            throw new IllegalStateException("Unable to build x509 Cert decoder", e);
        }
        return new CountryTrustAnchorValidator(new CertificateValidator(decoder));
    }

    CountryTrustAnchorValidator(CertificateValidator validator) {
        this.certificateValidator = validator;
    }

    Collection<String> findErrors(RSAKey anchor) {
        Collection<String> errors = new HashSet<>();

        if (!isKeyTypeRSA(anchor)) {
            errors.add(String.format("Expecting key type to be %s, was %s", KeyType.RSA, anchor.getKeyType()));
        }
        if (!isAlgorithmRS256(anchor)) {
            errors.add(String.format("Expecting algorithm to be %s, was %s", JWSAlgorithm.RS256, anchor.getAlgorithm()));
        }
        if (!isKeyOperationsVerify(anchor)) {
            errors.add(String.format("Expecting key operations to only contain %s", KeyOperation.VERIFY));
        }
        if (!isKeyIDPresent(anchor)) {
            errors.add("Expecting a KeyID");
        }

        if (hasCertificates(anchor)) {
            errors.addAll(validateCertificates(anchor));
        } else {
            errors.add("Expecting at least one X.509 certificate");
        }

        return errors;
    }

    private Collection<String> validateCertificates(RSAKey anchor) {
        PublicKey publicKey;
        try {
            publicKey = anchor.toPublicKey();
        } catch (JOSEException e) {
            return ImmutableList.of(String.format("Error getting public key from trust anchor: %s", e.getMessage()));
        }
        return certificateValidator.checkCertificateValidity(anchor.getX509CertChain(), publicKey);
    }

    private boolean isKeyTypeRSA(JWK anchor) {
        return Optional.ofNullable(anchor.getKeyType())
                .map(type -> type.equals(KeyType.RSA))
                .orElse(false);
    }

    private boolean isAlgorithmRS256(JWK anchor) {
        return Optional.ofNullable(anchor.getAlgorithm())
                .map(alg -> alg.equals(JWSAlgorithm.RS256))
                .orElse(false);
    }

    private boolean isKeyOperationsVerify(JWK anchor) {
        return Optional.ofNullable(anchor.getKeyOperations())
                .filter(ops -> ops.size() == 1)
                .map(ops -> ops.contains(KeyOperation.VERIFY))
                .orElse(false);
    }

    private boolean isKeyIDPresent(JWK anchor) {
        return Optional.ofNullable(anchor.getKeyID())
                .map(kid -> !kid.isEmpty())
                .orElse(false);
    }

    private boolean hasCertificates(JWK anchor) {
        return Optional.ofNullable(anchor.getX509CertChain())
                .map(certChain -> certChain.size() > 0)
                .orElse(false);
    }
}
