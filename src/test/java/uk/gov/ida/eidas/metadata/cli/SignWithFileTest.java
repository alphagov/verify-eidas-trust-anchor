package uk.gov.ida.eidas.metadata.cli;

import com.google.common.io.Resources;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import picocli.CommandLine;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.eidas.utils.FileReader;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

public class SignWithFileTest {

    private String metadataFilePath;
    private String outputFilePath;
    private String keyPath;
    private String certPath;
    private String wrongCertPath;

    @BeforeEach
    public void setUp() throws InitializationException {
        InitializationService.initialize();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        keyPath = Resources.getResource("pki/ecdsa.test.pk8").getPath();
        certPath = Resources.getResource("pki/ecdsa.test.crt").getPath();
        wrongCertPath = Resources.getResource("pki/diff_ecdsa.test.crt").getPath();

        String resourceDir = Resources.getResource("metadata/").getPath();
        outputFilePath = resourceDir + "signed-metadata.xml";
        metadataFilePath = resourceDir + "unsigned/metadata.xml";
    }

    @AfterEach
    public void tearDown(){
        new File(outputFilePath).delete();
    }

    @Test
    public void shouldWriteSignedMetadataToFile() throws IOException, CertificateEncodingException {
        CommandLine.call(new SignWithFile(), null,
            "--key=" + keyPath,
            "--cert=" + certPath,
            "-o=" + outputFilePath,
            metadataFilePath
        );

        String signedMetadata = FileReader.readFileContent(outputFilePath);
        X509Certificate certificate = new X509CertificateFactory().createCertificate(FileReader.readFileContent(certPath));
        assertThat(signedMetadata).contains(Base64.getEncoder().encodeToString(certificate.getEncoded()));
    }

    @Test
    public void shouldNotWriteToFileOnSigningError() {
        try {
            CommandLine.call(new SignWithFile(), null,
                "--key=" + keyPath,
                "--cert=" + wrongCertPath,
                "-o=" + outputFilePath,
                metadataFilePath
            );
            fail("should have errored when signing with wrong cert");
        } catch (Exception exception) {
            assertThat(exception.getMessage()).contains("SignatureException");
            assertThat(exception.getMessage()).contains("Unable to sign Connector Metadata");
            assertFalse("Should not create signed metadata file", new File(outputFilePath).exists());
        }
    }
}
