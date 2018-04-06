package uk.gov.ida.eidas.trustanchor.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.RunLast;

@Command(name = "tasign", description = "Signs trust anchors", subcommands = {
        Import.class,
        SignWithFile.class,
        SignWithSmartcard.class})
class Application implements Runnable {
    public static void main(String[] args) {
        CommandLine cmd = new CommandLine(new Application());
        cmd.parseWithHandler(new RunLast(), System.err, args);
    }

    @Override
    public void run() {
        // If we reach this point, we didn't match any subcommands.
        // So print the usage; there's nothing to do by default.
        CommandLine.usage(this, System.err);
    }
}