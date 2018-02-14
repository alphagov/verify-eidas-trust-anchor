package uk.gov.ida.trustanchor.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.RunLast;

@Command(name="tasign", description="Signs trust anchors", subcommands={SignWithFile.class, SignWithSmartcard.class})
class Application implements Runnable {
  public static void main(String[] args) {
    CommandLine cmd = new CommandLine(new Application());
    cmd.parseWithHandler(new RunLast(), System.err, args);
  }

  @Override
  public void run() {
    CommandLine.usage(this, System.err);
  }
}