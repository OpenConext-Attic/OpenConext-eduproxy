# OpenConext-eduproxy

[![Build Status](https://travis-ci.org/OpenConext/OpenConext-eduproxy.svg)](https://travis-ci.org/OpenConext/OpenConext-eduproxy)
[![codecov.io](https://codecov.io/gh/OpenConext/OpenConext-eduproxy/coverage.svg)](https://codecov.io/gh/OpenConext/OpenConext-eduproxy)

EDUProxy is a SAML Proxy acting as a Identity Provider for all eduGain Service Providers and
as a ServiceProvider for the OpenConext Identity Provider. The Proxy behaviour can be configured in order
for the EDUProxy to be used as a generic IdP-SP SAML proxy with hooks for authnResponse 'enrichment'.

## [Getting started](#getting-started)

### [System Requirements](#system-requirements)

- Java 7
- Maven 3

### [Building and running](#building-and-running)

This project uses Spring Boot and Maven. To run locally, type:

```bash
mvn spring-boot:run
```

When developing, it's convenient to just execute the applications main-method, which is in [Application](src/main/java/eduproxy/Application.java).

## [Private signing keys and public certificates](#signing-keys)

The SAML Spring Security library needs the following keys:

* private DSA key / public certificate pair for the eduProxy IdP / SP
* the public certificate of the real IdentityProvider
* the certificates of the Service Providers

The public certificate can be copied from the metadata. The private / public key for the EDUProxy SP / IDP can be generated:
 
```bash
openssl req -subj '/O=Organization, CN=EduProxy/' -newkey rsa:2048 -new -x509 -days 3652 -nodes -out eduproxy.crt -keyout eduproxy.pem
```

The Java KeyStore expects a pkcs8 DER format for RSA private keys so we have to re-format that key:

```bash
openssl pkcs8 -nocrypt  -in eduproxy.pem -topk8 -out eduproxy.der
```
 
Remove the whitespace, heading and footer from the eduproxy.crt and eduproxy.der:

```bash
cat eduproxy.der |head -n -1 |tail -n +2 | tr -d '\n'; echo
cat eduproxy.crt |head -n -1 |tail -n +2 | tr -d '\n'; echo
```

Above commands work on linux distributions. On mac you can issue the same command with `ghead` after you install `coreutils`:

```bash
brew install coreutils

cat eduproxy.der |ghead -n -1 |tail -n +2 | tr -d '\n'; echo
cat eduproxy.crt |ghead -n -1 |tail -n +2 | tr -d '\n'; echo
```

Add the eduproxy key pair to the application.properties file:

```bash
proxy.private_key=${output from cleaning the der file}
proxy.certificate=${output from cleaning the crt file}
```

Add the Identity Provider certificate to the application.properties file:

```bash
idp.certificate=${copy & paste from the metadata}
```

The Service Providers allowed to connect can be provided in a Metadata feed configured in ```application.yml```:

```yml
serviceproviders:
  feed: http://mds.edugain.org/
```
By default - but easily changed / overridden - only Service Providers with valid signing certificates in the SAML metadata
are allowed to connect. See [ServiceProviderFeedParser](src/main/java/eduproxy/saml/ServiceProviderFeedParser.java).

```yml
serviceproviders:
  require_signing: true
```

## [SAML metadata](#saml-metadata)

The metadata is generated - and cached - on the fly and is displayed on [http://localhost:8080/sp/metadata](http://localhost:8080/sp/metadata)
and [http://localhost:8080/idp/metadata](http://localhost:8080/idp/metadata)



