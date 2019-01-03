package uk.gov.ida.eidas.utils.keyloader;

import java.io.IOException;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Partially cribbed from net.shibboleth.tool.xmlsectool.CredentialHelper
 */
public class PKCS11KeyLoader {
  private final Provider provider;
  private final String keyPassword;

  public PKCS11KeyLoader(final Provider provider, final String keyPassword) {
    this.provider = provider;
    this.keyPassword = keyPassword;
  }

  public PrivateKey getSigningKey(String keyAlias) throws NoSuchAlgorithmException,
          UnrecoverableEntryException,
          KeyStoreException,
          SecurityException,
          IllegalArgumentException,
          IOException,
          CertificateException {
    final KeyStore keyStore = KeyStore.getInstance("PKCS11", this.provider);
    keyStore.load(null, keyPassword.toCharArray());
    final PrivateKeyEntry keyEntry = (PrivateKeyEntry)keyStore.getEntry(keyAlias,
            new KeyStore.PasswordProtection(keyPassword.toCharArray()));
    if (keyEntry == null) {
      throw new RuntimeException("Key store contains wrong kind of credential, need Private key");
    }
    PrivateKey privateKey = keyEntry.getPrivateKey();
    if (privateKey == null) {
      throw new RuntimeException("Key store didn't contain Private Key");
    }
    return privateKey;
  }

  public X509Certificate getPublicCertificate(String alias) throws CertificateException,
          NoSuchAlgorithmException,
          IOException,
          KeyStoreException {

    final KeyStore keyStore = KeyStore.getInstance("PKCS11", this.provider);
    keyStore.load(null, keyPassword.toCharArray());

    Certificate certificate = keyStore.getCertificate(alias);
    if (certificate.equals(null)) {
      throw new RuntimeException(("Certificate not found with alias: " + alias));
    }
    if (!(certificate instanceof X509Certificate)) {
      throw new RuntimeException("Certificate is not an X509Certificate");
    }
    return (X509Certificate) certificate;
  }
}
