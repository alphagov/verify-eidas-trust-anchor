package uk.gov.ida.eidas.cli.trustanchor;

import com.nimbusds.jose.jwk.JWK;
import org.json.JSONObject;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import uk.gov.ida.eidas.trustanchor.CountryTrustAnchor;
import uk.gov.ida.eidas.utils.keyloader.FileKeyLoader;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.concurrent.Callable;

@Command(name="import", description="Import a certificate file and generate a JWK from it")
class Import implements Callable<Void> {

    @Parameters(arity="1", index="0", description="The Key ID to assign, usually the metadata URL")
    private String keyId;

    @Parameters(arity="1..*", index="1", description="The certificate files to generate from")
    private File[] certificates;

    @Option(names={ "-o", "--output" }, description="File to output to. Defaults to stdout.", required=false)
    private File outputFile;

    @Override
    public Void call() throws Exception {
        JWK key = CountryTrustAnchor.make(FileKeyLoader.loadCerts(certificates), keyId);
        writeOut(this.outputFile, keyToPrettyString(key));
        return null;
    }

    private String keyToPrettyString(JWK key) {
        final int INDENT_FACTOR = 4;
        String uglyJsonString = key.toJSONObject().toJSONString();
        return new JSONObject(uglyJsonString).toString(INDENT_FACTOR);
    }

    private void writeOut(File outputFile, String outputString) throws IOException {
        OutputStreamWriter output = (outputFile == null ? new OutputStreamWriter(System.out) : new FileWriter(outputFile));
        output.write(outputString);
        output.close();
    }
}
