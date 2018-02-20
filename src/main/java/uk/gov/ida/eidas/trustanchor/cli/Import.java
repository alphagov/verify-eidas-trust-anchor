package uk.gov.ida.eidas.trustanchor.cli;

import java.io.File;
import java.io.FileWriter;
import java.io.OutputStreamWriter;
import java.util.concurrent.Callable;

import com.nimbusds.jose.jwk.JWK;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import uk.gov.ida.eidas.trustanchor.FileKeyLoader;
import uk.gov.ida.eidas.trustanchor.CountryTrustAnchor;

@Command(name="import", description="Import a certificate file and generate a JWK from it")
class Import implements Callable<Void> {
  @Parameters(arity="1", index="0", description="The certificate file to generate from")
  private File certificate;

  @Parameters(arity="1", index="1", description="The Key ID to assign, usually the metadata URL")
  private String keyId;

  @Option(names={ "-o", "--output" }, description="File to output to. Defaults to stdout.", required=false)
  private File outputFile;

	@Override
	public Void call() throws Exception {
    OutputStreamWriter output = (outputFile == null ? new OutputStreamWriter(System.out) : new FileWriter(outputFile));
    JWK key = CountryTrustAnchor.make(FileKeyLoader.loadCert(certificate), keyId);
    output.write(key.toJSONString());
    output.close();
		return null;
	}
}