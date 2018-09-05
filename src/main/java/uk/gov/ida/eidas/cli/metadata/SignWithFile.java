package uk.gov.ida.eidas.cli.metadata;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import uk.gov.ida.eidas.utils.keyloader.FileKeyLoader;

import java.io.File;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.concurrent.Callable;

@Command(name="sign-with-file", description="Signs the final key set with a key loaded from a file")
public class SignWithFile extends SigningCommand implements Callable<Void> {

  @Option(names = { "--key" }, description = "Location of the private key to use for signing", required=true)
  private File keyFile;

  @Option(names = { "--cert"}, description = "Public signing Certificate", required = true)
  private File certificateFile;

  @Override
  public Void call() throws Exception {
    ECPrivateKey key = FileKeyLoader.loadECKey(keyFile);
    X509Certificate x509Certificate = FileKeyLoader.loadCert(certificateFile);
    return build(key, x509Certificate);
  }
}