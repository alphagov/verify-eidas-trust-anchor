package uk.gov.ida.trustanchor.cli;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import uk.gov.ida.trustanchor.Generator;

abstract class SigningCommand {
  @Parameters(description = "The JSON Web Key (JWK) files to extract certificates from")
  private List<File> inputFiles = Collections.emptyList();

  @Option(names = { "-o", "--output" }, description = "File to write the signed trust anchor to", required = true)
  private File outputFile;

  public Void build(RSAPrivateKey key) throws Exception {
    Stream<File> nonReadable = inputFiles.stream().filter(f -> !f.canRead());
    if (nonReadable.count() != 0) {
      String missingFiles = nonReadable.map(File::getPath).collect(Collectors.joining());
      throw new FileNotFoundException("Could not read files: " + missingFiles);
    }

    if (! (outputFile.canWrite() || (!outputFile.exists() && outputFile.getAbsoluteFile().getParentFile().canWrite()))) {
      throw new FileNotFoundException("Cannot write to output file: " + outputFile.getAbsolutePath());
    }

    Stream<String> inputs = inputFiles.stream().map(this::readFile);
    final Generator generator = new Generator(key);
    final String generatedAnchors = generator.generate(inputs);

    final FileWriter output = new FileWriter(outputFile);
    output.write(generatedAnchors);
    output.close();

    return null;
  }

  private String readFile(File file) {
    try {
      return new String(Files.readAllBytes(file.toPath()));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
