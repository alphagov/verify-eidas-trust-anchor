package uk.gov.ida.eidas.metadata.cli;

import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.common.SignableSAMLObject;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import uk.gov.ida.eidas.metadata.ConnectorMetadataSigner;
import uk.gov.ida.eidas.metadata.MetadataSignatureValidator;
import uk.gov.ida.eidas.metadata.saml.SamlObjectMarshaller;
import uk.gov.ida.eidas.utils.FileReader;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.OutputStreamWriter;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

abstract class SigningCommand {
    @Parameters(description = "The SAML Metadata XML file to sign.")
    private File inputFile;

    @Option(names = {"-o", "--output"}, description = "The file to write the signed SAML Metadata XML to.", required = false)
    private File outputFile;

    public Void build(PrivateKey key, X509Certificate certificate) throws Exception {
        if (!inputFile.canRead()) {
            throw new FileNotFoundException("Could not read file: " + inputFile.getPath());
        }

        if (outputFile != null && !(outputFile.canWrite() || (!outputFile.exists() && outputFile.getAbsoluteFile().getParentFile().canWrite()))) {
            throw new FileNotFoundException("Cannot write to output file: " + outputFile.getAbsolutePath());
        }

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        InitializationService.initialize();

        String metadataString = FileReader.readFileContent(inputFile);

        SignableSAMLObject signedMetadataObject = new ConnectorMetadataSigner(certificate, key).sign(metadataString);

        boolean valid = new MetadataSignatureValidator(certificate.getPublicKey(), key).validate(signedMetadataObject);
        if(!valid) throw new SignatureException("Unable to sign Connector Metadata");

        SamlObjectMarshaller marshaller = new SamlObjectMarshaller();
        String signedMetadata = marshaller.transformToString(signedMetadataObject);

        final OutputStreamWriter output = (outputFile == null ? new OutputStreamWriter(System.out) : new FileWriter(outputFile));
        output.write(signedMetadata);
        output.close();

        return null;
    }
}