package uk.gov.ida.eidas.trustanchor.cli.trustanchor;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import uk.gov.ida.eidas.utils.keyloader.PKCS11KeyLoader;

import java.io.File;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;

@Command(name="sign-with-smartcard", description="Signs the final key set with a key from a smartcard")
public class SignWithSmartcard extends SignTrustAnchor implements Callable<Void> {
    @Option(names = { "--config" }, description = "PKCS#11 configuration passed as a file.\nSee https://tinyurl.com/pkcs11config", required=true)
    private File pkcs11Config;

    @Option(names = { "--key" }, description = "Alias of the key on the smartcard", required=true)
    private String keyAlias;

    @Option(names = { "--password" }, description = "Password of the key on the smartcard", required=true)
    private String password;

    @Option(names = { "--cert" }, description = "Alias of the public certificate on the smartcard", required=true)
    private String certAlias;

    @Override
    public Void call() throws Exception {
         Provider provider = Security.getProvider("SunPKCS11").configure(pkcs11Config.getAbsolutePath());
         Security.addProvider(provider);

         PKCS11KeyLoader keyLoader = new PKCS11KeyLoader(provider, password);
         PrivateKey key = keyLoader.getSigningKey(keyAlias);
         X509Certificate certificate = keyLoader.getPublicCertificate(certAlias);
         return build(key, certificate);
    }
}
