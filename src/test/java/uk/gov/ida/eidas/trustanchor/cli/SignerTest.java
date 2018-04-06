package uk.gov.ida.eidas.trustanchor.cli;

import com.google.common.collect.ImmutableList;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SignerTest {

    @Test
    public void testSignerThrowsExceptionWhenInputFileNotReadable() throws Exception {

        PrivateKey key = mock(PrivateKey.class);
        X509Certificate certificate = mock(X509Certificate.class);

        File inputFile = mock(File.class);
        when(inputFile.getPath()).thenReturn("test");
        when(inputFile.canRead()).thenReturn(false);
        List<File> inputFiles = ImmutableList.of(inputFile);

        File outputFile = mock(File.class);

        Signer signer = new Signer(key, certificate, inputFiles, outputFile);

        Assertions.assertThrows(FileNotFoundException.class, signer::sign);
    }
}
