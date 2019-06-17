package uk.gov.ida.eidas.trustanchor.cli.trustanchor;

        import picocli.CommandLine;
        import picocli.CommandLine.Command;

@Command(name="trust-anchor", description="Generates and Signs trust anchors. You can also choose to print the content of encoded trust anchors.", subcommands={
        Import.class,
        Print.class,
        SignWithFile.class,
        SignWithSmartcard.class})
public class TrustAnchorGenerationApplication implements Runnable {
    @Override
    public void run() {
        // If we reach this point, we didn't match any subcommands.
        // So print the usage; there's nothing to do by default.
        CommandLine.usage(this, System.err);
    }
}