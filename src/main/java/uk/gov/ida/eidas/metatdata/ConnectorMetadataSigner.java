package uk.gov.ida.eidas.metatdata;

import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import uk.gov.ida.saml.deserializers.parser.SamlObjectParser;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ConnectorMetadataSigner {
    private PrivateKey key;
    private X509Certificate certificate;

    public ConnectorMetadataSigner(X509Certificate certificate, PrivateKey key) {
        this.key = key;
        this.certificate = certificate;
    }

    public SignableSAMLObject sign(String metadataString) throws CertificateEncodingException, XMLParserException, UnmarshallingException {
        SamlObjectParser sop = new SamlObjectParser();
        SignableSAMLObject metadata = sop.getSamlObject(metadataString);

        String certificateString = Base64.getEncoder().encodeToString(this.certificate.getEncoded());
        SamlObjectSigner samlObjectSigner = new SamlObjectSigner(
                this.certificate.getPublicKey(),
                key,
                certificateString,
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1);
        samlObjectSigner.sign(metadata);

        return metadata;
    }
}
