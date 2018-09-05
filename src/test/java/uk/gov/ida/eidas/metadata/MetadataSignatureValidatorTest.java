package uk.gov.ida.eidas.metadata;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.google.common.io.Resources;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class MetadataSignatureValidatorTest {

    private PrivateKey privateKeyForSigning;
    private X509Certificate certificateForSigning;
    private X509Certificate wrongCertificate;

    @BeforeEach
    void setUp() throws InitializationException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        root.setLevel(Level.OFF);

        InitializationService.initialize();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        privateKeyForSigning = FileKeyLoader.loadECKey(new File(Resources.getResource("pki/ecdsa.test.pk8").getFile()));
        certificateForSigning = FileKeyLoader.loadCert(new File(Resources.getResource("pki/ecdsa.test.crt").getFile()));
        wrongCertificate = FileKeyLoader.loadCert(new File(Resources.getResource("pki/diff_ecdsa.test.crt").getFile()));
    }

    @Test
    public void shouldReturnTrueIfSignatureMatchesKeyPair() throws IOException, SignatureException, SecurityException, XMLParserException, UnmarshallingException, CertificateEncodingException {
        SignableSAMLObject signedMetadataSaml = loadMetadataAndSign("metadata/unsigned/metadata.xml", certificateForSigning);

        MetadataSignatureValidator signatureValidator = new MetadataSignatureValidator(certificateForSigning.getPublicKey(), privateKeyForSigning);
        boolean result = signatureValidator.validate(signedMetadataSaml);

        assertTrue(result);
    }

    @Test
    public void shouldReturnFalseIfSignatureDoesNotMatchKeyPair() throws IOException, XMLParserException, UnmarshallingException, CertificateEncodingException, SignatureException, SecurityException {
        SignableSAMLObject signedMetadataSaml = loadMetadataAndSign("metadata/unsigned/metadata.xml", wrongCertificate);

        MetadataSignatureValidator signatureValidator = new MetadataSignatureValidator(wrongCertificate.getPublicKey(), privateKeyForSigning);
        boolean result = signatureValidator.validate(signedMetadataSaml);

        assertFalse(result);
    }

    private SignableSAMLObject loadMetadataAndSign(String resourceFilePath, X509Certificate certificateForSigning) throws IOException, XMLParserException, UnmarshallingException, CertificateEncodingException {
        File file = new File(Resources.getResource(resourceFilePath).getFile());
        String metadataString = FileReader.readFileContent(file);
        return new ConnectorMetadataSigner(certificateForSigning, privateKeyForSigning).sign(metadataString);
    }
}