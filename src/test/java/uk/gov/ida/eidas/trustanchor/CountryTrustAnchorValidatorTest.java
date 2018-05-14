package uk.gov.ida.eidas.trustanchor;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;

import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static com.nimbusds.jose.jwk.KeyOperation.VERIFY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CountryTrustAnchorValidatorTest {

    private CertificateValidator mockValidator = mock(CertificateValidator.class);
    private final CountryTrustAnchorValidator testValidator = new CountryTrustAnchorValidator(mockValidator);

    @BeforeEach
    public void setup() {
        when(mockValidator.checkCertificateValidity(any(), any())).thenReturn(ImmutableList.of());
    }

    @Test
    public void validTrustAnchorShouldRaiseNoExceptions() {
        RSAKey validTrustAnchor = getValidTrustAnchor();
        Collection<String> errors = testValidator.findErrors(validTrustAnchor);

        assertThat(errors).isEmpty();
    }

    private RSAKey getValidTrustAnchor() {

        RSAPublicKey mockPublicKey = mock(RSAPublicKey.class);
        BigInteger value = BigInteger.valueOf(2).pow(512);
        value.bitLength();
        when(mockPublicKey.getModulus()).thenReturn(value);
        when(mockPublicKey.getPublicExponent()).thenReturn(BigInteger.valueOf(512));
        return new RSAKey.Builder(mockPublicKey)
                .keyID("TestId")
                .x509CertChain(ImmutableList.of(mock(Base64.class)))
                .algorithm(RS256)
                .keyOperations(ImmutableSet.of(VERIFY))
                .build();
    }
}
