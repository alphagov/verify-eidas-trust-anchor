package uk.gov.ida.eidas.trustanchor.cli;

import java.io.File;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import uk.gov.ida.eidas.trustanchor.FileKeyLoader;

@Command(name="sign-with-file", description="Signs the final key set with a key loaded from a file")
public class SignWithFile extends SigningCommand implements Callable<Void> {
  @Option(names = { "--key" }, description = "Location of the private key to use for signing", required=true)
  private File keyFile;

  @Option(names = { "--cert"}, description = "Public signing Certificate", required = true)
  private File certificateFile;

  @Override
  public Void call() throws Exception {
    RSAPrivateKey key = FileKeyLoader.load(keyFile);
    X509Certificate x509Certificate = FileKeyLoader.loadCert(certificateFile);
    return build(key, x509Certificate);
  }
}
