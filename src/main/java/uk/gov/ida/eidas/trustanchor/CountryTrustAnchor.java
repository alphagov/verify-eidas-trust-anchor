package uk.gov.ida.eidas.trustanchor;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;

public class CountryTrustAnchor {
  public static JWK make(X509Certificate certificate, String keyId) throws CertificateEncodingException {
    RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
    if (publicKey == null) {
      throw new RuntimeException(String.format(
        "Certificate public key in wrong format, got %s, expecting %s",
        certificate.getPublicKey().getClass().getName(),
        RSAPublicKey.class.getName()));
    }

    Base64 base64cert = Base64.encode(certificate.getEncoded());
    RSAKey key = new RSAKey.Builder(publicKey)
      .algorithm(JWSAlgorithm.RS256)
      .keyOperations(Collections.singleton(KeyOperation.VERIFY))
      .keyID(keyId)
      .x509CertChain(Collections.singletonList(base64cert))
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
    if (anchor.getX509CertChain() == null || anchor.getX509CertChain().size() != 1) {
      errors.add(String.format("Expecting exactly one X.509 certificate"));
    } else {
      InputStream certStream = new ByteArrayInputStream(anchor.getX509CertChain().get(0).decode());
      try {
        Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(certStream);
        if(!certificate.getPublicKey().equals(((RSAKey)anchor).toPublicKey())) {
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
