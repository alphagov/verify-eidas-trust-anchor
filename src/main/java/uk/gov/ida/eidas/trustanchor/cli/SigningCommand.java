package uk.gov.ida.eidas.trustanchor.cli;

import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

abstract class SigningCommand {
    @Parameters(description = "The JSON Web Key (JWK) files to extract certificates from")
    private List<File> inputFiles;

    @Option(names = {"-o", "--output"}, description = "File to write the signed trust anchor to", required = false)
    private File outputFile;

    public Void build(PrivateKey key, X509Certificate certificate) throws Exception {
        return new Signer(key, certificate, this.inputFiles, this.outputFile).sign();
    }
}
