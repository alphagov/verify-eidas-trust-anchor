package uk.gov.ida.eidas.metadata;

import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import picocli.CommandLine;
import uk.gov.ida.eidas.metatdata.cli.SignWithFile;
import uk.gov.ida.saml.core.test.PemCertificateStrings;
import uk.gov.ida.saml.core.test.TestCertificateStrings;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

public class SignWithFileTest {

    private File keyFile;
    private File certFile;

    private String keyFilePath;
    private String certFilePath;
    private String metadataFilePath;
    private String outputFilePath;

    @Before
    public void setUp() throws IOException, InitializationException {
        String resourceDir = this.getClass().getClassLoader().getResource("./").getPath();

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        InitializationService.initialize();

        outputFilePath = resourceDir + "metadata/signed-metadata.xml";
        keyFilePath = resourceDir + "keyFile";
        certFilePath = resourceDir + "certFile";
        metadataFilePath = resourceDir + "metadata/unsigned/metadata.xml";

        keyFile = writeToFile(keyFilePath, Base64.getDecoder().decode(TestCertificateStrings.METADATA_SIGNING_A_PRIVATE_KEY));
        certFile = writeToFile(certFilePath, PemCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT.getBytes());
    }

    private static File writeToFile(String filename, byte[] fileContent) throws IOException {
        File file = new File(filename);
        FileUtils.writeByteArrayToFile(file, fileContent);
        return file;
    }

    @After
    public void tearDown(){
        keyFile.delete();
        certFile.delete();
    }

    @Test
    public void shouldSignMetadata() throws IOException {
        CommandLine.call(new SignWithFile(), null,
            "--key=" + keyFilePath,
            "--cert=" + certFilePath,
            "-o=" + outputFilePath,
            metadataFilePath
        );

        String signedMetadata = new String(Files.readAllBytes(Paths.get(outputFilePath)), StandardCharsets.UTF_8);

        assertThat(signedMetadata).contains(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT.replaceAll("\n", ""));
    }
}
