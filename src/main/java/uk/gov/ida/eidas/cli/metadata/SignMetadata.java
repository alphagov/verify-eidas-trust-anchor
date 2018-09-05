package uk.gov.ida.eidas.cli.metadata;

import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import uk.gov.ida.eidas.metadata.SignedMetadataGenerator;

import java.io.File;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

abstract class SignMetadata {
    @Parameters(description = "The SAML Metadata XML file to sign.")
    private File inputFile;

    @Option(names = {"-o", "--output"}, description = "The file to write the signed SAML Metadata XML to.", required = false)
    private File outputFile;

    public Void build(PrivateKey key, X509Certificate certificate) throws Exception {
        return new SignedMetadataGenerator(key, certificate, inputFile, outputFile).generate();
    }
}
