package uk.gov.ida.eidas.metadata.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(name="sign-connector-metadata", description="Signs Connector Metadata", subcommands={SignWithFile.class})
public class ConnectorMetadataSigningApplication implements Runnable {
    @Override
    public void run() {
        // If we reach this point, we didn't match any subcommands.
        // So print the usage; there's nothing to do by default.
        CommandLine.usage(this, System.err);
    }
}
