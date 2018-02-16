package uk.gov.ida.trustanchor;

import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

/**
 * Partially cribbed from net.shibboleth.tool.xmlsectool.CredentialHelper
 */
public class PKCS11KeyLoader {
  private final Class<? extends Provider> provider;
  private final String pkcs11Config;
  private final String keyAlias;
  private final String keyPassword;

  public PKCS11KeyLoader(final Class<? extends Provider> provider, final String pkcs11Config, final String keyAlias, final String keyPassword) {
    this.provider = provider;
    this.pkcs11Config = pkcs11Config;
    this.keyAlias = keyAlias;
    this.keyPassword = keyPassword;
  }

  public PrivateKey getSigningKey() throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
          NoSuchMethodException, SecurityException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, IOException, CertificateException {
    final KeyStore keyStore = getKeyStore(this.pkcs11Config, this.provider);
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

  private static KeyStore getKeyStore(String pkcs11Config, Class<? extends Provider> klazz) throws NoSuchMethodException, SecurityException, InstantiationException,
          IllegalAccessException, IllegalArgumentException, InvocationTargetException, IOException, KeyStoreException {
    final Constructor<? extends Provider> constructor = klazz.getConstructor(String.class);
    final Provider provider = constructor.newInstance(pkcs11Config);
    provider.load(new StringReader(pkcs11Config));
    Security.addProvider(provider);
    return KeyStore.getInstance("PKCS11", provider);
  }
}
