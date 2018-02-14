package uk.gov.ida.trustanchor;

import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

public class Generator {
  private final JWKSetSigner signer;

  public Generator(RSAPrivateKey signingKey) {
    this.signer = new JWKSetSigner(signingKey, null);
  }

  public String generate(Stream<String> inputFiles) throws JOSEException {
    return generateJson(inputFiles).serialize();
  }

  public JWSObject generateJson(Stream<String> inputFiles) throws JOSEException {
    List<JWK> certs = inputFiles.map(this::makeJWK).collect(Collectors.toList());
    JWKSet certSet = new JWKSet(certs);

    JWSObject signedCerts = signer.sign(certSet);

    return signedCerts;
  }

  public JWK makeJWK(String yaml) {
    try {
      return JWK.parse(yaml);
    } catch (ParseException e) {
      throw new RuntimeException(e);
    }
  }
}
