package uk.gov.ida.eidas.metadata;

import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.common.shared.security.PrivateKeyFactory;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.eidas.metatdata.ConnectorMetadataSigner;
import uk.gov.ida.eidas.metatdata.MetadataSignatureValidator;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.deserializers.parser.SamlObjectParser;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class MetadataSignatureValidatorTest {

    private PrivateKey privateKeyForSigning;
    private X509Certificate certificateForSigning;
    private X509Certificate wrongCertificate;

    @BeforeEach
    void setUp() throws InitializationException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        InitializationService.initialize();
        privateKeyForSigning = new PrivateKeyFactory().createPrivateKey(Base64.decodeBase64(TestCertificateStrings.METADATA_SIGNING_A_PRIVATE_KEY));
        certificateForSigning = new X509CertificateFactory().createCertificate(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT);
        wrongCertificate = new X509CertificateFactory().createCertificate(TestCertificateStrings.METADATA_SIGNING_B_PUBLIC_CERT);
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
        ClassLoader classLoader = this.getClass().getClassLoader();
        File file = new File(classLoader.getResource(resourceFilePath).getFile());

        String metadataString = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        String signedMetadata = new ConnectorMetadataSigner(privateKeyForSigning, certificateForSigning).sign(metadataString);

        return new SamlObjectParser().getSamlObject(signedMetadata);
    }
}