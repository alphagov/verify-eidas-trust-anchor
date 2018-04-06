package uk.gov.ida.eidas.trustanchor;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

public class CountryTrustAnchor {
    public static JWK make(List<X509Certificate> certificates, String keyId) throws CertificateEncodingException {
        List<PublicKey> invalidPublicKeys = certificates.stream()
                .map(c -> c.getPublicKey())
                .filter(key -> !(key instanceof RSAPublicKey))
                .collect(Collectors.toList());

        if (!invalidPublicKeys.isEmpty()) {
            throw new RuntimeException(String.format(
                    "Certificate public key(s) in wrong format, got %s, expecting %s",
                    String.join(" ", invalidPublicKeys.stream().map(key -> key.getClass().getName()).collect(Collectors.toList())),
                    RSAPublicKey.class.getName()));
        }

        RSAPublicKey publicKey = (RSAPublicKey) certificates.get(0).getPublicKey();
        List<Base64> encodedCertChain = certificates.stream().map(certificate -> {
            try {
                return Base64.encode(certificate.getEncoded());
            } catch (CertificateEncodingException e) {
                throw new RuntimeException(e);
            }
        }).collect(Collectors.toList());

        RSAKey key = new RSAKey.Builder(publicKey)
                .algorithm(JWSAlgorithm.RS256)
                .keyOperations(Collections.singleton(KeyOperation.VERIFY))
                .keyID(keyId)
                .x509CertChain(encodedCertChain)
                .build();

        Collection<String> errors = findErrors(key);
        if (!errors.isEmpty()) {
            throw new Error(String.format("Managed to generate an invalid anchor: %s", String.join(", ", errors)));
        }

        return key;
    }

    public static JWK parse(String json) throws ParseException {
        JWK key = JWK.parse(json);

        Collection<String> errors = findErrors(key);
        if (!errors.isEmpty()) {
            throw new ParseException(String.format("JWK was not a valid trust anchor: %s", String.join(", ", errors)), 0);
        }

        return key;
    }

    public static Collection<String> findErrors(JWK anchor) {
        Collection<String> errors = new HashSet<String>();
        if (anchor.getKeyType() == null || !anchor.getKeyType().equals(KeyType.RSA))
            errors.add(String.format("Expecting key type to be %s, was %s", KeyType.RSA, anchor.getKeyType()));
        if (anchor.getAlgorithm() == null || !anchor.getAlgorithm().equals(JWSAlgorithm.RS256))
            errors.add(String.format("Expecting algorithm to be %s, was %s", JWSAlgorithm.RS256, anchor.getAlgorithm()));
        if (anchor.getKeyOperations() == null || anchor.getKeyOperations().size() != 1 || !anchor.getKeyOperations().contains(KeyOperation.VERIFY))
            errors.add(String.format("Expecting key operations to only contain %s", KeyOperation.VERIFY));
        if (anchor.getKeyID() == null || anchor.getKeyID().isEmpty())
            errors.add(String.format("Expecting a KeyID"));
        if (anchor.getX509CertChain() == null || anchor.getX509CertChain().size() == 0) {
            errors.add(String.format("Expecting at least one X.509 certificate"));
        } else {
            InputStream certStream = new ByteArrayInputStream(anchor.getX509CertChain().get(0).decode());
            try {
                Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(certStream);
                if (!certificate.getPublicKey().equals(((RSAKey) anchor).toPublicKey())) {
                    errors.add(String.format("X.509 Certificate does not match the public key"));
                }
            } catch (CertificateException e) {
                errors.add(String.format("X.509 certificate factory not available", e.getMessage()));
            } catch (JOSEException e) {
                errors.add(String.format("Error getting public key from trust anchor", e.getMessage()));
            }
        }
        return errors;
    }
}
