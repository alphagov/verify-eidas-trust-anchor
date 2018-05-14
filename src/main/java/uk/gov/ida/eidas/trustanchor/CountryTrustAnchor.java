package uk.gov.ida.eidas.trustanchor;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;

import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class CountryTrustAnchor {

  public static JWK make(List<X509Certificate> certificates, String keyId) {

      List<PublicKey> invalidPublicKeys = certificates.stream()
              .map(X509Certificate::getPublicKey)
              .filter(key -> !(key instanceof RSAPublicKey))
              .collect(Collectors.toList());

    if (!invalidPublicKeys.isEmpty()) {
      throw new RuntimeException(String.format(
        "Certificate public key(s) in wrong format, got %s, expecting %s",
        String.join(" ", invalidPublicKeys.stream().map(key -> key.getClass().getName()).collect(Collectors.toList())),
        RSAPublicKey.class.getName()));
    }

    RSAPublicKey publicKey = (RSAPublicKey) certificates.get(0).getPublicKey();

      List<Base64> encodedSortedCertChain = CertificateSorter.sort(certificates).stream()
              .map(certificate -> {
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
      .x509CertChain(encodedSortedCertChain)
      .build();

    Collection<String> errors = CountryTrustAnchorValidator.build().findErrors(key);
    if (!errors.isEmpty()) {
      throw new Error(String.format("Managed to generate an invalid anchor: %s", String.join(", ", errors)));
    }

    return key;
  }

    public static JWK parse(String json) throws ParseException {
        JWK key = JWK.parse(json);

        Collection<String> errors = findTrustAnchorErrors(key);

        if (!errors.isEmpty()) {
            throw new ParseException(String.format("JWK was not a valid trust anchor: %s", String.join(", ", errors)), 0);
        }

        return key;
    }

    /**
     * Deprecated - use {@link CountryTrustAnchorValidator} instead
     */
    @Deprecated
    public static Collection<String> findErrors(JWK trustAnchor) {
        return findTrustAnchorErrors(trustAnchor);
    }

    private static Collection<String> findTrustAnchorErrors(JWK trustAnchor) {
        Collection<String> errors;
        if (trustAnchor instanceof RSAKey) {
            errors = CountryTrustAnchorValidator.build().findErrors((RSAKey) trustAnchor);
        } else {
            errors = new ArrayList<>();
            errors.add(String.format("Expecting key type to be %s, was %s", KeyType.RSA, trustAnchor.getKeyType()));
        }
        return errors;
    }
}
