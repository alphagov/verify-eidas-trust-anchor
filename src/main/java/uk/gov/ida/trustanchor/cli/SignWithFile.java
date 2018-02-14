package uk.gov.ida.trustanchor.cli;

import java.io.File;
import java.security.interfaces.RSAPrivateKey;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import uk.gov.ida.trustanchor.FileKeyLoader;

@Command(name="sign-with-file", description="Signs the final key set with a key loaded from a file")
public class SignWithFile extends SigningCommand implements Callable<Void> {
  @Option(names = { "--key" }, description = "Location of the private key to use for signing", required=true)
  private File keyFile;

  @Override
  public Void call() throws Exception {
    RSAPrivateKey key = FileKeyLoader.load(keyFile);
    return build(key);
  }
}
