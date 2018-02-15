package uk.gov.ida.trustanchor;

import java.text.ParseException;
import java.util.Collection;

import com.nimbusds.jose.jwk.JWK;

public class CountryTrustAnchor {
  public static JWK parse(String json) throws ParseException {
    JWK key = JWK.parse(json);

    return key;
  }
}
