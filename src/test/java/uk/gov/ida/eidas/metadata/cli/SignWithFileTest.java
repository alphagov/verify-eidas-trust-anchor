package uk.gov.ida.eidas.metadata.cli;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import uk.gov.ida.eidas.utils.FileReader;
import uk.gov.ida.saml.core.test.PemCertificateStrings;
import uk.gov.ida.saml.core.test.TestCertificateStrings;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

public class SignWithFileTest {

    private File keyFile;
    private File certFile;
    private File wrongCertFile;

    private String keyFilePath;
    private String certFilePath;
    private String wrongCertFilePath;

    private String metadataFilePath;
    private String outputFilePath;

    @BeforeEach
    public void setUp() throws IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
        String resourceDir = this.getClass().getClassLoader().getResource("metadata/").getPath();
        outputFilePath = resourceDir + "signed-metadata.xml";
        keyFilePath = resourceDir + "keyFile";
        certFilePath = resourceDir + "certFile";
        wrongCertFilePath = resourceDir + "wrongCertFile";
        metadataFilePath = resourceDir + "unsigned/metadata.xml";

        keyFile = writeToFile(keyFilePath, Base64.getDecoder().decode(TestCertificateStrings.METADATA_SIGNING_A_PRIVATE_KEY));
        certFile = writeToFile(certFilePath, PemCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT.getBytes());
        wrongCertFile = writeToFile(wrongCertFilePath, PemCertificateStrings.METADATA_SIGNING_B_PUBLIC_CERT.getBytes());
    }

    @AfterEach
    public void tearDown(){
        keyFile.delete();
        certFile.delete();
        wrongCertFile.delete();
        new File(outputFilePath).delete();
    }

    @Test
    public void shouldSignMetadata() throws IOException {
        CommandLine.call(new SignWithFile(), null,
            "--key=" + keyFilePath,
            "--cert=" + certFilePath,
            "-o=" + outputFilePath,
            metadataFilePath
        );

        String signedMetadata = FileReader.readFileContent(outputFilePath);
        assertThat(signedMetadata).contains(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT.replaceAll("\n", ""));
    }

    @Test
    public void shouldErrorAndNotWriteToFileIfMetadataNotSigned() {
        try {
            CommandLine.call(new SignWithFile(), null,
                "--key=" + keyFilePath,
                "--cert=" + wrongCertFilePath,
                "-o=" + outputFilePath,
                metadataFilePath
            );
            fail();
        } catch (Exception exception) {
            assertThat(exception.getMessage()).contains("SignatureException");
            assertThat(exception.getMessage()).contains("Unable to sign Connector Metadata");
            assertFalse("Should not create signed metadata file", new File(outputFilePath).exists());
        }
    }

    private static File writeToFile(String filename, byte[] fileContent) throws IOException {
        File file = new File(filename);
        FileUtils.writeByteArrayToFile(file, fileContent);
        return file;
    }
}
