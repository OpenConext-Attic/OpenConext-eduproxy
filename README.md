# OpenConext-saml-proxy

[![Build Status](https://travis-ci.org/OpenConext/OpenConext-eduproxy.svg)](https://travis-ci.org/OpenConext/OpenConext-eduproxy)
[![codecov.io](https://codecov.io/github/OpenConext/OpenConext-eduproxy/coverage.svg)](https://codecov.io/github/OpenConext/OpenConext-eduproxy)

EDUProxy which is a SAML Service Provider and SAML Identity Provider.

## [Getting started](#getting-started)

### [System Requirements](#system-requirements)

- Java 7
- Maven 3

### [Building and running](#building-and-running)

This project uses Spring Boot and Maven. To run locally, type:

```bash
mvn spring-boot:run -Drun.jvmArguments="-Dspring.profiles.active=dev"
```

When developing, it's convenient to just execute the applications main-method, which is in [Application](src/main/java/eduproxy/Application.java).

## [Private signing keys and public certificates](#signing-keys)

The SAML Spring Security library needs a private DSA key and the public certificates of the IdentityProviders. The public certificates can be copied
from the metadata. The private / public key for the EDUProxy SP can be generated:
 
```bash
openssl req -subj '/O=Organization, CN=AttributeMapper/' -newkey rsa:2048 -new -x509 -days 3652 -nodes -out oidc.crt -keyout am.pem
```

The Java KeyStore expects a pkcs8 DER format for RSA private keys so we have to re-format that key:

```bash
openssl pkcs8 -nocrypt  -in am.pem -topk8 -out am.der
```
 
Remove the whitespace, heading and footer from the am.crt and am.der:

```bash
cat am.der |head -n -1 |tail -n +2 | tr -d '\n'; echo
cat am.crt |head -n -1 |tail -n +2 | tr -d '\n'; echo
```

Above commands work on linux distributions. On mac you can issue the same command with `ghead` after you install `coreutils`:

```bash
brew install coreutils

cat am.der |ghead -n -1 |tail -n +2 | tr -d '\n'; echo
cat am.crt |ghead -n -1 |tail -n +2 | tr -d '\n'; echo
```

Add the am key pair to the application.properties file:

```bash
sp.private.key=${output from cleaning the der file}
sp.certificate=${output from cleaning the crt file}
```

Add the EB certificate to the application.properties file:

```bash
idp.certificate=${copy & paste from the metadata}
```

## [SAML metadata](#saml-metadata)

The metadata is generated on the fly and is displayed on http://localhost:8080/saml/metadata



