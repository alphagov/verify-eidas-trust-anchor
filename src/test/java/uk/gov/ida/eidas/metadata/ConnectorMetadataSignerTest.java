package uk.gov.ida.eidas.metadata;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.google.common.io.Resources;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.slf4j.LoggerFactory;
import uk.gov.ida.eidas.utils.FileReader;
import uk.gov.ida.eidas.utils.keyloader.FileKeyLoader;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ConnectorMetadataSignerTest {

    private PrivateKey privateKeyForSigning;
    private X509Certificate certificateForSigning;

    @BeforeEach
    void setUp() throws InitializationException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        root.setLevel(Level.OFF);

        InitializationService.initialize();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        privateKeyForSigning = FileKeyLoader.loadECKey(new File(Resources.getResource("pki/ecdsa.test.pk8").getFile()));
        certificateForSigning = FileKeyLoader.loadCert(new File(Resources.getResource("pki/ecdsa.test.crt").getFile()));
    }

    @Test
    public void shouldSignMetadata() throws IOException, CertificateEncodingException, XMLParserException, UnmarshallingException {
        String metadataString = loadMetadataString("metadata/unsigned/metadata.xml");

        SignableSAMLObject signedMetadata = new ConnectorMetadataSigner(certificateForSigning, privateKeyForSigning).sign(metadataString);
        Signature signature = signedMetadata.getSignature();

        assertThat(metadataString).doesNotContain(Base64.encodeBase64String(certificateForSigning.getEncoded()));
        assertTrue(signedMetadata.isSigned());
        assertEquals(privateKeyForSigning, signature.getSigningCredential().getPrivateKey());
        assertEquals(certificateForSigning.getPublicKey(), signature.getSigningCredential().getPublicKey());
        assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA256, signature.getSignatureAlgorithm());
    }

    @Test
    public void shouldErrorWhenMetadataEmpty() {
        assertThrows(XMLParserException.class,
                ()->new ConnectorMetadataSigner(certificateForSigning, privateKeyForSigning).sign(""));
    }

    @Test
    public void shouldErrorWhenMetadataNull() {
        assertThrows(NullPointerException.class,
                ()->new ConnectorMetadataSigner(certificateForSigning, privateKeyForSigning).sign(null));
    }

    @Test
    public void shouldErrorWhenMetadataInvalid() throws IOException {
        String metadataString = loadMetadataString("metadata/unsigned/bad-metadata.xml");
        assertThrows(UnmarshallingException.class,
                ()->new ConnectorMetadataSigner(certificateForSigning, privateKeyForSigning).sign(metadataString));
    }

    private String loadMetadataString(String resourceFilePath) throws IOException {
        ClassLoader classLoader = this.getClass().getClassLoader();
        File file = new File(classLoader.getResource(resourceFilePath).getFile());

        return FileReader.readFileContent(file);
    }
}
