package uk.gov.ida.eidas.trustanchor.cli.trustanchor;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import uk.gov.ida.eidas.trustanchor.cli.metadata.SignMetadata;
import uk.gov.ida.eidas.utils.keyloader.FileKeyLoader;

import java.io.File;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;

import static uk.gov.ida.eidas.metadata.AlgorithmType.RSA;

@Command(name="sign-with-file", description="Signs the final key set with a key loaded from a file")
public class SignWithFile extends SignMetadata implements Callable<Void> {

    @Option(names = { "--key" }, description = "Location of the private key to use for signing", required=true)
    private File keyFile;

    @Option(names = { "--cert"}, description = "Public signing Certificate", required = true)
    private File certificateFile;

    @Override
    public Void call() throws Exception {
        SignMetadata.initialize();

        PrivateKey key = algorithm == RSA ? FileKeyLoader.loadRSAKey(keyFile) : FileKeyLoader.loadECKey(keyFile);
        X509Certificate x509Certificate = FileKeyLoader.loadCert(certificateFile);
        return build(key, x509Certificate, algorithm);
    }
}
