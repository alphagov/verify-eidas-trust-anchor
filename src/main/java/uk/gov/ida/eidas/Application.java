package uk.gov.ida.eidas;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import uk.gov.ida.eidas.metadata.cli.ConnectorMetadataSigningApplication;
import uk.gov.ida.eidas.trustanchor.cli.TrustAnchorGenerationApplication;

@Command(name="eidas-trust-tool", description="Generates and Signs eIDAS artifacts", subcommands={
    TrustAnchorGenerationApplication.class,
    ConnectorMetadataSigningApplication.class
})
public class Application implements Runnable {
    public static void main(String[] args) {
        CommandLine application = new CommandLine(new Application());
        application.parseWithHandler(new CommandLine.RunLast(), System.err, args);
    }

    @Override
    public void run() {
        // If we reach this point, we didn't match any subcommands.
        // So print the usage; there's nothing to do by default.
        CommandLine.usage(this, System.err);
    }
}
