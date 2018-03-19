package uk.gov.ida.eidas.trustanchor.cli;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import uk.gov.ida.eidas.trustanchor.Generator;

abstract class SigningCommand {
  @Parameters(description = "The JSON Web Key (JWK) files to extract certificates from")
  private List<File> inputFiles;

  @Option(names = { "-o", "--output" }, description = "File to write the signed trust anchor to", required = false)
  private File outputFile;

  public Void build(PrivateKey key, X509Certificate certificate) throws Exception {
    Stream<File> nonReadable = inputFiles.stream().filter(f -> !f.canRead());
    if (nonReadable.count() != 0) {
      String missingFiles = nonReadable.map(File::getPath).collect(Collectors.joining());
      throw new FileNotFoundException("Could not read files: " + missingFiles);
    }

    if (outputFile != null && !(outputFile.canWrite() || (!outputFile.exists() && outputFile.getAbsoluteFile().getParentFile().canWrite()))) {
      throw new FileNotFoundException("Cannot write to output file: " + outputFile.getAbsolutePath());
    }

    List<String> inputs = new ArrayList<>(inputFiles.size());
    for (File input : inputFiles) {
      inputs.add(new String(Files.readAllBytes(input.toPath())));
    }
    final Generator generator = new Generator(key, certificate);
    final String generatedAnchors = generator.generate(inputs).serialize();

    final OutputStreamWriter output = (outputFile == null ? new OutputStreamWriter(System.out) : new FileWriter(outputFile));
    output.write(generatedAnchors);
    output.close();

    return null;
  }
}
