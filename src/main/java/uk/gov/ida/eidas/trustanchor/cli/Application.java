package uk.gov.ida.eidas.trustanchor.cli;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.GlobalParserPoolInitializer;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.core.xml.schema.impl.XSAnyMarshaller;
import org.opensaml.core.xml.schema.impl.XSAnyUnmarshaller;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyName;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.KeyInfoMarshaller;
import org.opensaml.xmlsec.signature.impl.KeyInfoUnmarshaller;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.impl.SignatureMarshaller;
import org.opensaml.xmlsec.signature.impl.SignatureUnmarshaller;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataMarshaller;
import org.opensaml.xmlsec.signature.impl.X509DataUnmarshaller;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import uk.gov.ida.eidas.trustanchor.cli.metadata.ConnectorMetadataSigningApplication;
import uk.gov.ida.eidas.trustanchor.cli.metadata.ProxyNodeMetadataSigningApplication;
import uk.gov.ida.eidas.trustanchor.cli.trustanchor.TrustAnchorGenerationApplication;

import java.security.Security;


@Command(name="eidas-trust-tool", description="Generates and Signs eIDAS artifacts", subcommands={
    TrustAnchorGenerationApplication.class,
    ConnectorMetadataSigningApplication.class,
    ProxyNodeMetadataSigningApplication.class
})
public class Application implements Runnable {

    public static void main(String[] args) throws InitializationException {
        Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        root.setLevel(Level.INFO);

        new GlobalParserPoolInitializer().init();

        InitializationService.initialize();
        Security.addProvider(new BouncyCastleProvider());


        XMLObjectProviderRegistrySupport.registerObjectProvider(
                KeyInfo.DEFAULT_ELEMENT_NAME,
                new KeyInfoBuilder(),
                new KeyInfoMarshaller(),
                new KeyInfoUnmarshaller());

        XMLObjectProviderRegistrySupport.registerObjectProvider(
                KeyName.DEFAULT_ELEMENT_NAME,
                new XSAnyBuilder(),
                new XSAnyMarshaller(),
                new XSAnyUnmarshaller());

        XMLObjectProviderRegistrySupport.registerObjectProvider(
                X509Data.DEFAULT_ELEMENT_NAME,
                new X509DataBuilder(),
                new X509DataMarshaller(),
                new X509DataUnmarshaller()
        );

        XMLObjectProviderRegistrySupport.registerObjectProvider(
                X509Certificate.DEFAULT_ELEMENT_NAME,
                new X509CertificateBuilder(),
                new X509DataMarshaller(),
                new X509DataUnmarshaller()
        );

        XMLObjectProviderRegistrySupport.registerObjectProvider(
                Signature.DEFAULT_ELEMENT_NAME,
                new SignatureBuilder(),
                new SignatureMarshaller(),
                new SignatureUnmarshaller()
        );

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
