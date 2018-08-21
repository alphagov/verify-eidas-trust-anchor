package uk.gov.ida.eidas.trustanchor.cli;

import com.nimbusds.jose.JWSObject;

import org.json.JSONArray;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import uk.gov.ida.eidas.utils.FileReader;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name="print", description="Print a trust anchor file in JSON format")
class Print implements Callable<Void> {

    @Parameters(arity="0..*", index="0", description="Trust anchor files to load and display.")
    private List<File> anchors = new ArrayList<>();

    @Option(names={ "-o", "--output" }, description="File to output to. Defaults to stdout.", required=false)
    private File outputFile;

    @Override
    public Void call() throws Exception {
        final int INDENT_FACTOR = 4;
        JSONArray anchorObjects = new JSONArray();

        for (File anchor : anchors) {
            String encodedJwsObject = FileReader.readFileContent(anchor);
            anchorObjects.put(JWSObject.parse(encodedJwsObject).getPayload().toJSONObject());
        }

        writeOut(this.outputFile, anchorObjects.toString(INDENT_FACTOR));
        return null;
    }

    private void writeOut(File outputFile, String outputString) throws IOException {
        OutputStreamWriter output = (outputFile == null ? new OutputStreamWriter(System.out) : new FileWriter(outputFile));
        output.write(outputString);
        output.close();
    }
}
