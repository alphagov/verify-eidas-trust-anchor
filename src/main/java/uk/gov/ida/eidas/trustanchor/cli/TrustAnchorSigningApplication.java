package uk.gov.ida.eidas.trustanchor.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(name="sign-trust-anchor", description="Signs trust anchors", subcommands={
  Import.class,
  Print.class,
  SignWithFile.class,
  SignWithSmartcard.class})
public class TrustAnchorSigningApplication implements Runnable {
  @Override
  public void run() {
    // If we reach this point, we didn't match any subcommands.
    // So print the usage; there's nothing to do by default.
    CommandLine.usage(this, System.err);
  }
}