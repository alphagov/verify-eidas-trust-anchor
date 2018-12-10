package uk.gov.ida.eidas.cli;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import org.opensaml.core.config.InitializationException;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import uk.gov.ida.eidas.cli.metadata.ConnectorMetadataSigningApplication;
import uk.gov.ida.eidas.cli.trustanchor.TrustAnchorGenerationApplication;

@Command(name="eidas-trust-tool", description="Generates and Signs eIDAS artifacts", subcommands={
    TrustAnchorGenerationApplication.class,
    ConnectorMetadataSigningApplication.class
})
public class Application implements Runnable {
    public static void main(String[] args) throws InitializationException {
        Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        root.setLevel(Level.INFO);

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
