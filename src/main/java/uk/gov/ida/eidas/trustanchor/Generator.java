package uk.gov.ida.eidas.trustanchor;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

public class Generator {
  private final JWKSetSigner signer;

  public Generator(PrivateKey signingKey, X509Certificate certificate) {
    this.signer = new JWKSetSigner(signingKey, null, certificate);
  }

  public String generate(List<String> inputFiles) throws JOSEException, ParseException, CertificateEncodingException {
    return generateJson(inputFiles).serialize();
  }

  public JWSObject generateJson(List<String> inputFiles) throws JOSEException, ParseException, CertificateEncodingException {
    List<JWK> certs = new ArrayList<JWK>();
    for (String input : inputFiles) {
      certs.add(CountryTrustAnchor.parse(input));
    }

    JWKSet certSet = new JWKSet(certs);
    JWSObject signedCerts = signer.sign(certSet);

    return signedCerts;
  }
}
