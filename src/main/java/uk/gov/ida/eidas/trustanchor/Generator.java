package uk.gov.ida.eidas.trustanchor;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import net.minidev.json.JSONObject;
import uk.gov.ida.common.shared.security.X509CertificateFactory;

public class Generator {
  private final JWKSetSigner signer;

  public Generator(PrivateKey signingKey, X509Certificate certificate) {
    this.signer = new JWKSetSigner(signingKey, null, certificate);
  }

  public JWSObject generateFromMap(Map<String, String> trustAnchorMap) throws ParseException, JOSEException, CertificateEncodingException {
    List<String> inputFiles = trustAnchorMap.entrySet().stream()
            .map(entry -> buildJsonObject(entry.getKey(), entry.getValue()))
            .collect(Collectors.toList());

    return generate(inputFiles);
  }

  public JWSObject generate(List<String> inputFiles) throws JOSEException, ParseException, CertificateEncodingException {
    List<JWK> certs = new ArrayList<>();
    for (String input : inputFiles) {
      certs.add(CountryTrustAnchor.parse(input));
    }

    return signer.sign(new JWKSet(certs));
  }

  private String buildJsonObject(String keyId, String certificate) {
    X509Certificate x509Certificate = new X509CertificateFactory().createCertificate(certificate);
    RSAPublicKey publicKey = (RSAPublicKey) x509Certificate.getPublicKey();
    JSONObject jsonObject = new JSONObject();
    jsonObject.put("kty", "RSA");
    jsonObject.put("key_ops", Collections.singletonList("verify"));
    jsonObject.put("kid", keyId);
    jsonObject.put("alg", "RS256");
    jsonObject.put("e", new String (Base64.getEncoder().encode(publicKey.getPublicExponent().toByteArray())));
    jsonObject.put("n", new String (Base64.getEncoder().encode(publicKey.getModulus().toByteArray())));
    jsonObject.put("x5c", Collections.singletonList(certificate));

    return jsonObject.toJSONString();
  }
}
