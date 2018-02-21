package uk.gov.ida.eidas.trustanchor;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import net.minidev.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.ida.common.shared.security.PrivateKeyFactory;
import uk.gov.ida.common.shared.security.PublicKeyFactory;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.saml.core.test.TestCertificateStrings;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GeneratorTest {

    private Generator generator;

    private RSAPublicKey publicKey;

    @BeforeEach
    public void setUp(){
        PrivateKey privateKey = new PrivateKeyFactory().createPrivateKey(Base64.decodeBase64(TestCertificateStrings.UNCHAINED_PRIVATE_KEY));
        generator = new Generator(privateKey);
        publicKey = (RSAPublicKey) new PublicKeyFactory(new X509CertificateFactory()).createPublicKey(TestCertificateStrings.UNCHAINED_PUBLIC_CERT);
    }

    @Test
    public void shouldHandleZeroInput() throws ParseException, JOSEException {
        List<String> files = new ArrayList<>();

        JWSObject output = generator.generateJson(files);

        assertSigned(output, publicKey);
        assertTrue(output.getPayload().toJSONObject().containsKey("keys"));
        assertTrue(((List<Object>)output.getPayload().toJSONObject().get("keys")).isEmpty());
    }

    @Test
    public void shouldHandleOneString() throws ParseException, JOSEException {
        List<String> files = new ArrayList<>();
        files.add(createJsonObject().toJSONString());
        JWSObject output = generator.generateJson(files);

        assertSigned(output, publicKey);
        assertTrue(output.getPayload().toJSONObject().containsKey("keys"));

        List<JSONObject> keys = (List<JSONObject>) output.getPayload().toJSONObject().get("keys");
        assertEquals(1, keys.size());
        assertEquals("https://generator.test",keys.get(0).getAsString("kid"));
    }

    @Test
    public void shouldThrowOnMissingValue() {
        List<String> valueList = Arrays.asList("kty", "key_ops", "kid", "alg", "e", "n", "x5c");

        for (String attribute : valueList){
            JSONObject invalid = createJsonObject();
            invalid.remove(attribute);
            assertThrows(ParseException.class, () -> generator.generateJson(Collections.singletonList(invalid.toJSONString())));
        }
    }

    @Test
    public void shouldThrowOnIncorrectValue(){
        Map<String, Object> incorrectValues = new HashMap<String, Object>();
        incorrectValues.put("alg","A128KW");
        incorrectValues.put("kty", "oct");

        for (String attribute: incorrectValues.keySet()){
            JSONObject jsonObject = createJsonObject();
            jsonObject.replace(attribute, incorrectValues.get(attribute));
            assertThrows(ParseException.class, () -> generator.generateJson(Collections.singletonList(jsonObject.toJSONString())));
        }
    }

    @Test
    public void shouldThrowOnIncorrectKeyopsValues(){
        List<Object> incorrectValues = Arrays.asList(Arrays.asList(), Arrays.asList("sign"), Arrays.asList("verify", "sign"), "verify");

        for (Object attribute: incorrectValues){
            JSONObject jsonObject = createJsonObject();
            jsonObject.replace("key_ops", attribute);
            assertThrows(ParseException.class, () -> generator.generateJson(Collections.singletonList(jsonObject.toJSONString())));
        }
    }

    @Test
    public void shouldThrowWhenCertificateDoesNotMatchKeyParameters(){
        JSONObject jsonObject = createJsonObject();
        jsonObject.replace("x5c", Collections.singletonList(TestCertificateStrings.TEST_PUBLIC_CERT));

        assertThrows(ParseException.class, () -> generator.generateJson(Collections.singletonList(jsonObject.toJSONString())));
    }

    @Test
    public void shouldThrowOnOneInvalidKey() {
        List<String> files = new ArrayList<>();
        files.add(createJsonObject("https://1.generator.test").toJSONString());
        JSONObject invalidObject = createJsonObject("https://2.generator.test");
        invalidObject.remove("kid");
        files.add(invalidObject.toJSONString());

        assertThrows(ParseException.class, () -> generator.generateJson(files));
    }

    @Test
    public void shouldHandleMultipleStrings() throws ParseException, JOSEException {
        List<String> files = new ArrayList<>();
        for (int i = 0; i < 1024; i++) {
            files.add(createJsonObject(String.format("https://%d.generator.test", i)).toJSONString());
        }
        JWSObject output = generator.generateJson(files);

        assertSigned(output, publicKey);
        assertTrue(output.getPayload().toJSONObject().containsKey("keys"));

        List<JSONObject> keys = (List<JSONObject>) output.getPayload().toJSONObject().get("keys");
        Set<String> kidSet = keys.stream().map(x -> x.getAsString("kid")).collect(Collectors.toSet());

        assertEquals(1024, kidSet.size());
        for (int i = 0; i < 1024; i++) {
            assertTrue(kidSet.contains(String.format("https://%d.generator.test", i)));
        }
    }

    private JSONObject createJsonObject(){
        return createJsonObject("https://generator.test");
    }

    private JSONObject createJsonObject(String kid){
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("kty", "RSA");
        jsonObject.put("key_ops", Collections.singletonList("verify"));
        jsonObject.put("kid", kid);
        jsonObject.put("alg", "RS256");
        jsonObject.put("e", new String (Base64.encodeInteger(publicKey.getPublicExponent())));
        jsonObject.put("n", new String (Base64.encodeInteger(publicKey.getModulus())));
        jsonObject.put("x5c", Collections.singletonList(TestCertificateStrings.UNCHAINED_PUBLIC_CERT));

        return jsonObject;
    }

    private void assertSigned(JWSObject output, RSAPublicKey signedKey) throws JOSEException {
        assertEquals(JWSObject.State.SIGNED, output.getState());
        assertNotNull(output.getSignature());
        assertNotEquals("", output.getSignature().decodeToString());
        assertTrue(output.verify(new RSASSAVerifier(signedKey)));
    }

}
