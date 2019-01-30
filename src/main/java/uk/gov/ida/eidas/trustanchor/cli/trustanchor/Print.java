package uk.gov.ida.eidas.trustanchor.cli.trustanchor;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import org.json.JSONArray;
import net.minidev.json.JSONObject;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import uk.gov.ida.eidas.trustanchor.CountryTrustAnchorValidator;
import uk.gov.ida.eidas.trustanchor.InvalidTrustAnchorException;
import uk.gov.ida.eidas.utils.FileReader;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name="print", description="Print a trust anchor file in JSON format")
class Print implements Callable<Void> {

    @Parameters(arity="0..*", index="0", description="Trust anchor files to load and display.")
    private List<File> anchors = new ArrayList<>();

    @Option(names={ "-o", "--output" }, description="File to output to. Defaults to stdout.", required=false)
    private File outputFile;

    private CountryTrustAnchorValidator validator = CountryTrustAnchorValidator.build();

    @Override
    public Void call() throws Exception {
        final int INDENT_FACTOR = 4;
        JSONArray anchorObjects = new JSONArray();
        List<String> invalidFiles = new ArrayList<String>();

        for (File anchor : anchors) {
            String encodedJwsObject = FileReader.readFileContent(anchor);
            JSONObject jws = JWSObject.parse(encodedJwsObject).getPayload().toJSONObject();
            List<JWK> keys = JWKSet.parse(jws).getKeys();
            boolean valid = keysAreValid(keys);
            if (!valid) invalidFiles.add(anchor.getPath());
            anchorObjects.put(jws);
        }

        writeOut(this.outputFile, anchorObjects.toString(INDENT_FACTOR));
        if (!invalidFiles.isEmpty()) throw new InvalidTrustAnchorException("These JWKs did not pass validation:" + String.join(",\n", invalidFiles));
        return null;
    }

    private boolean keysAreValid(List<JWK> keys) {
        return keys.stream()
            .map(validator::findErrors)
            .flatMap(Collection::stream)
            .peek(System.err::println)
            .count() == 0;
    }

    private void writeOut(File outputFile, String outputString) throws IOException {
        OutputStreamWriter output = (outputFile == null ? new OutputStreamWriter(System.out) : new FileWriter(outputFile));
        output.write(outputString);
        output.close();
    }
}
