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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class CountryTrustAnchor {

  public static JWK make(List<X509Certificate> certificates, String keyId) {
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
    if (!hasCertificates(anchor)) {
      errors.add("Expecting at least one X.509 certificate");
    } else {
      errors.addAll(checkCertificateValidity(anchor, errors));
    }

    return errors;
  }

  private static Collection<String> checkCertificateValidity(JWK anchor, Collection<String> errors) {
    try {
      X509Certificate x509Certificate = getX509Certificate(anchor.getX509CertChain().get(0));

      if (!x509Certificate.getPublicKey().equals(((RSAKey) anchor).toPublicKey())) {
        errors.add(String.format("X.509 Certificate does not match the public key"));
      }
      for (Base64 base64cert : anchor.getX509CertChain()) {
        X509Certificate certificate = getX509Certificate(base64cert);
        certificate.checkValidity();
      }
    } catch (CertificateExpiredException e) {
      errors.add(String.format("X.509 certificate has expired", e.getMessage()));
    } catch (JOSEException e) {
      errors.add(String.format("Error getting public key from trust anchor", e.getMessage()));
    } catch (CertificateException e) {
      errors.add(String.format("X.509 certificate factory not available", e.getMessage()));
    }
    return errors;
  }

  private static boolean isKeyTypeRSA(JWK anchor){
	return Optional.ofNullable(anchor.getKeyType())
			.map(type -> type.equals(KeyType.RSA))
			.orElse(false);
  }

  private static boolean isAlgorithmRS256(JWK anchor){
	return Optional.ofNullable(anchor.getAlgorithm())
			.map(alg -> alg.equals(JWSAlgorithm.RS256))
			.orElse(false);
  }

  private static boolean isKeyOperationsVerify(JWK anchor){
    return Optional.ofNullable(anchor.getKeyOperations())
    		.filter(ops -> ops.size() == 1)
    		.map(ops -> ops.contains(KeyOperation.VERIFY))
    		.orElse(false);
  }

  private static boolean isKeyIDPresent(JWK anchor){
    return Optional.ofNullable(anchor.getKeyID())
    		.map(kid -> !kid.isEmpty())
    		.orElse(false);
  }

  private static boolean hasCertificates(JWK anchor){
    return Optional.ofNullable(anchor.getX509CertChain())
    		.map(certChain -> certChain.size() > 0)
    		.orElse(false);
  }

  private static X509Certificate getX509Certificate(Base64 base64) throws CertificateException {
      InputStream certStream = new ByteArrayInputStream(base64.decode());
      return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certStream);
  }
}
