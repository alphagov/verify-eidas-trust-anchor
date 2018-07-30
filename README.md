Verify eIDAS Trust Anchor Generator
===================================

[![Build Status](https://travis-ci.org/alphagov/verify-eidas-trust-anchor.svg?branch=master)](https://travis-ci.org/alphagov/verify-eidas-trust-anchor)

[European identity schemes](https://ec.europa.eu/digital-single-market/en/e-identification) each have unique metadata containing their identity providers and public keys. Every metadata file is signed with a country-specific key which allows metadata consumers to trust its authenticity.

We collect certificates for connected European countries into one place and sign them all together with a Verify key.

Our relying parties can trust the collection of certificates because of the [GOV.UK Verify](https://gov.uk/verify) certificate, and then trust individual metadata files by using the collection. This signed collection is called the ‘signed trust anchor’.

GOV.UK Verify expresses these anchors as [JSON Web Keys (JWK)](https://tools.ietf.org/html/rfc7517) and serves them signed in compact [JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515) format.

This tool can:
* generate trust anchors from a country's certificate
* aggregate many trust anchors together
* sign the aggregated anchors into a full signed trust anchor
* print a full signed trust anchor to show its constituent keys

## Build

Build the tool using `gradle`.

    # For Unix:
    ./gradlew build

    # For Windows:
    .\gradlew.bat build

If you make changes, run the tests.

    ./gradlew test

## Run

The build process will produce a JAR artifact which accepts multiple commands. All of the following commands are assumed to be prefixed with:

    java -jar verify-trust-anchor.jar ...

All commands by default will output to standard out. You can pass the `--output <file>` or `-o <file>` option to output to a file instead.

### Import

Generates a country's trust anchor by supplying the location of its metadata and its certificate or multiple certificates if the country has a certificate chain.

    ... import "https://metadata.example.com/example-country.xml" path/to/signing.crt [path/to/signing_ca.crt [...]]

### Sign with file

Aggregates and signs a collection of trust anchors by using a RSA private key supplied by a file. You can specify as many trust anchors as desired, including none.

    ... sign-with-file --key path/to/private-key.pk8 --cert path/to/public-cert.crt [country1.jwk [country2.jwk [...]]]

### Sign with smartcard

Aggregates and signs a collection of trust anchors by using a smartcard (such as a Yubikey) that can be accessed using PKCS11.

    ... sign-with-smartcard \
      --config pkcs11_config.txt \
      --key "Private Key alias" \
      --cert "Public Certificate alias" \
      --password 12345

This requires an external native library, such as [OpenSC](https://github.com/opensc/opensc). The config file will [passed to the PKCS11 provider as configuration](https://docs.oracle.com/javase/8/docs/technotes/guides/security/p11guide.html#P11Provider). For OpenSC, the correct config file might be:

    library = /usr/local/lib/opensc-pkcs11.so
    name = opensc

### Print

Prints the human-readable JSON representation of each signed trust anchor passed, contained in a JSON array. If no signed trust anchors are passed, an empty array is printed.

    ... print [trust-anchor.jwt [...]]

## Support and raising issues

If you think you have discovered a security issue in this code please email [disclosure@digital.cabinet-office.gov.uk](mailto:disclosure@digital.cabinet-office.gov.uk) with details.

For non-security related bugs and feature requests please [raise an issue](https://github.com/alphagov/verify-eidas-trust-anchor/issues/new) in the GitHub issue tracker.

## Licence

Licensed under the [MIT Licence](./LICENSE).
