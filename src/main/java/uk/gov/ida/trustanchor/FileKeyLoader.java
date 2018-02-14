package uk.gov.ida.trustanchor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class FileKeyLoader {

  private static final String ALGORITHM = "RSA";

  public static RSAPrivateKey load(final File keyFile) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
    final KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
    return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keyFile.toPath())));
  }
}
