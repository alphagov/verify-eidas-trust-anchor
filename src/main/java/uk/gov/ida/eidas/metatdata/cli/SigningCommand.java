package uk.gov.ida.eidas.metatdata.cli;

import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import uk.gov.ida.eidas.metatdata.ConnectorMetadataSigner;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

abstract class SigningCommand {
    @Parameters(description = "The SAML Metadata XML file to sign.")
    private File inputFile;

    @Option(names = {"-o", "--output"}, description = "The file to write the signed SAML Metadata XML to.", required = false)
    private File outputFile;

    public Void build(PrivateKey key, X509Certificate certificate) throws Exception {
        if (!inputFile.canRead()) {
            throw new FileNotFoundException("Could not read file: " + inputFile.getPath());
        }

        if (outputFile != null && !(outputFile.canWrite() || (!outputFile.exists() && outputFile.getAbsoluteFile().getParentFile().canWrite()))) {
            throw new FileNotFoundException("Cannot write to output file: " + outputFile.getAbsolutePath());
        }

        String metadataString = new String(Files.readAllBytes(inputFile.toPath()), "UTF-8");

        String signedMetadata = new ConnectorMetadataSigner(key, certificate).sign(metadataString);

        final OutputStreamWriter output = (outputFile == null ? new OutputStreamWriter(System.out) : new FileWriter(outputFile));
        output.write(signedMetadata);
        output.close();

        return null;
    }
}
