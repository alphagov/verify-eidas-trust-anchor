package uk.gov.ida.trustanchor.cli;

import java.io.File;
import java.security.PrivateKey;
import java.util.concurrent.Callable;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import uk.gov.ida.trustanchor.PKCS11KeyLoader;

@Command(name="sign-with-smartcard", description="Signs the final key set with a key from a smartcard")
public class SignWithSmartcard extends SigningCommand implements Callable<Void> {
  @Option(names = { "-l", "--lib" }, description = "Location of the card access library (e.g. \"opensc.so\")", required=true)
  private File library;

  @Option(names = { "--symbol" }, description = "The name of the library symbol to call (e.g. \"opensc\")", required=true)
  private String name;

  @Option(names = { "--key" }, description = "Alias of the key on the smartcard", required=true)
  private String alias;

  @Option(names = { "--password" }, description = "Password of the key on the smartcard", required=true)
  private String password;

  @Override
  public Void call() throws Exception {
    final String config = String.format("--\nname=%s\nlibrary=%s", name, library.getAbsolutePath());
    PrivateKey key = new PKCS11KeyLoader(sun.security.pkcs11.SunPKCS11.class, config, alias, password).getSigningKey();

    return build(key);
  }
}
