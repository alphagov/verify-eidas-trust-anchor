package uk.gov.ida.eidas.metadata;

import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.io.UnmarshallingException;
import uk.gov.ida.common.shared.security.PrivateKeyFactory;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.eidas.metatdata.ConnectorMetadataSigner;
import uk.gov.ida.saml.core.test.TestCertificateStrings;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ConnectorMetadataSignerTest {

    PrivateKey privateKeyForSigning;
    X509Certificate certificateForSigning;

    @BeforeEach
    void setUp() throws InitializationException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        InitializationService.initialize();
        privateKeyForSigning = new PrivateKeyFactory().createPrivateKey(Base64.decodeBase64(TestCertificateStrings.METADATA_SIGNING_A_PRIVATE_KEY));
        certificateForSigning = new X509CertificateFactory().createCertificate(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT);

    }

    @Test
    public void shouldSignMetadata() throws IOException, CertificateEncodingException, XMLParserException, UnmarshallingException {

        String metadataString = loadMetadataString("metadata/unsigned/metadata.xml");
        String signedMetadata = new ConnectorMetadataSigner(privateKeyForSigning, certificateForSigning).sign(metadataString);

        assertThat(metadataString).doesNotContain(Base64.encodeBase64String(certificateForSigning.getEncoded()));
        assertThat(signedMetadata).contains(Base64.encodeBase64String(certificateForSigning.getEncoded()));
    }

    @Test
    public void shouldErrorWhenMetadataEmpty() {
        assertThrows(XMLParserException.class,
                ()->new ConnectorMetadataSigner(privateKeyForSigning, certificateForSigning).sign(""));
    }

    @Test
    public void shouldErrorWhenMetadataNull() {
        assertThrows(NullPointerException.class,
                ()->new ConnectorMetadataSigner(privateKeyForSigning, certificateForSigning).sign(null));
    }

    @Test
    public void shouldErrorWhenMetadataInvalid() throws IOException {
        String metadataString = loadMetadataString("metadata/unsigned/bad-metadata.xml");
        assertThrows(UnmarshallingException.class,
                ()->new ConnectorMetadataSigner(privateKeyForSigning, certificateForSigning).sign(metadataString));
    }

    private String loadMetadataString(String resourceFilePath) throws IOException {
        ClassLoader classLoader = this.getClass().getClassLoader();
        File file = new File(classLoader.getResource(resourceFilePath).getFile());

        return new String(Files.readAllBytes(file.toPath()), "UTF-8");
    }
}
