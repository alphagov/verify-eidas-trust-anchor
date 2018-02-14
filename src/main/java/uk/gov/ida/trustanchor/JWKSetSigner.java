package uk.gov.ida.trustanchor;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64URL;
import java.security.interfaces.RSAPrivateKey;

class JWKSetSigner {

  private final Base64URL thumbprint;
  private final RSAPrivateKey privateKey;

  public JWKSetSigner(RSAPrivateKey privateKey, Base64URL thumbprint) {
    this.privateKey = privateKey;
    this.thumbprint = thumbprint;
  }

  public JWSObject sign(JWKSet tokenSet) throws JOSEException {
    final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                  .x509CertThumbprint(thumbprint)
                  .build();

    final JWSObject jwsObject = new JWSObject(header, new Payload(tokenSet.toJSONObject()));

    final JWSSigner signer = new RSASSASigner(privateKey);
    jwsObject.sign(signer);

    return jwsObject;
  }
}