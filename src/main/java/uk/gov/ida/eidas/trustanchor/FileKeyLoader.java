package uk.gov.ida.eidas.trustanchor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class FileKeyLoader {

  private static final String ALGORITHM = "RSA";
  private static final String CERTIFICATE_TYPE = "X.509";

  public static RSAPrivateKey load(final File keyFile) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
    final KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
    return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keyFile.toPath())));
  }

  public static X509Certificate loadCert(final File certFile) {
    try {
      CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
      return (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(certFile));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static List<X509Certificate> loadCerts(final File[] certFiles) {
    return Arrays.stream(certFiles)
            .map(FileKeyLoader::loadCert)
            .collect(Collectors.toList());
  }
}
