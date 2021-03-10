package uk.gov.ida.eidas.trustanchor.cli.metadata;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(name="proxy-node-metadata", description="Signs Proxy Node Metadata", subcommands={
    SignWithFile.class,
    SignWithSmartcard.class
})
public class ProxyNodeMetadataSigningApplication implements Runnable {
    @Override
    public void run() {
        // If we reach this point, we didn't match any subcommands.
        // So print the usage; there's nothing to do by default.
        CommandLine.usage(this, System.err);
    }
}
