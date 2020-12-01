<!--
Copyright (c) 2019 Siemens AG
Licensed under the Apache License, Version 2.0
SPDX-License-Identifier: Apache-2.0
-->

# Lightweight CMP RA

This project provides a Proof of Concept (PoC) implementation of the
[Lightweight CMP Profile](https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/)
for CMP [[RFC 4210]](https://tools.ietf.org/html/rfc4210).

## License

This software is licensed under the Apache License, Version 2.0.

# Disclaimer

This prototypical code explicitly does not have production quality
but constructively proves that the Lightweight CMP Profile
can be implemented and used.
Some effort has been spent on software quality &mdash; for instance,
static code analyzers (like SpotBugs), clean code concepts,
and best practice recommendations in secure configuration are used.
Nevertheless it is explicitly not guaranteed that all related functionality
and hardening measures needed for productive software have been implemented.
The development procedures and processes for proof-of-concept
implementation are not sufficient to assure product-grade software quality.
Therefore the code, scripts, and configuration of the PoC are provided 'as is'
and can only serve as an example for developers.

# Usage

## Preconditions

* The *Java SE Development Kit (JDK)*.
  The Lightweight CMP RA has been developed under JDK 1.8.\
  It can be found at
  <https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html>.
* The *Apache Maven tool*.
  For details, documentation, and download see <http://maven.apache.org/>.
* The *GIT version control system*.
  For details, documentation, and download see <http://git-scm.com/>.

On a Debian-like system the packages can be installed, e.g., using

```
sudo apt install adoptopenjdk-8-hotspot maven git
```

## Downloading the sources

```bash
git clone https://github.com/siemens/LightweightCmpRa.git
cd LightweightCmpRa
git checkout master
```

## Building the project

```bash
mvn clean install
```

This includes running unit test, which may also be invoked explicitly by

```bash
mvn test
```

## Running the RA

Example XML configuration files can be found at
[src/test/java/com/siemens/pki/lightweightcmpra/test/config](
 src/test/java/com/siemens/pki/lightweightcmpra/test/config)
and after installation also at `target/test-classes`.

```bash
cd target/test-classes
java -jar ../LightweightCmpRa-0.0.1-SNAPSHOT.jar <XML configuration File>
```

For standalone start it is recommended  to export a "Runnable JAR file" and have 
the required libraries in a subfolder.


# Software architecture

## External components

This implementation uses [BouncyCastle](https://www.bouncycastle.org/)
for CMP-related basic functions and some cryptographic operations.

The [Simple Logging Facade for Java (SLF4J)](http://www.slf4j.org/)
serves as a simple facade or abstraction for various logging frameworks
(e.g., `java.util.logging`, `logback`, `log4j`).
If the [SimpleLogger](http://www.slf4j.org/apidocs/org/slf4j/impl/SimpleLogger.html) is used,
full logging can be enabled by giving  `-Dorg.slf4j.simpleLogger.log.com.siemens=debug` as first command line option. 

The [Eclipse Californium](https://www.eclipse.org/californium/)
is used for CoAP support.

The [JUnit testing framework](https://junit.org/)
is used for implementing some tests.

## Internal structure

* In the Java package [`com.siemens.pki.lightweightcmpra.msggeneration`](
               src/main/com/siemens/pki/lightweightcmpra/msggeneration/)
  all functions related to message generation can be found.
* The package [`com.siemens.pki.lightweightcmpra.msgvalidation`](
       src/main/com/siemens/pki/lightweightcmpra/msgvalidation/)
  provides classes and functions needed for CMP message validation.
* CMP Message protection is done by the classes located in
         [`com.siemens.pki.lightweightcmpra.protection`](
  src/main/com/siemens/pki/lightweightcmpra/protection/).
* The basic crypto functions and utilities for signing, encryption and key generation 
         are located in 
         [`com.siemens.pki.lightweightcmpra.cryptoservices`](
  src/main/com/siemens/pki/lightweightcmpra/cryptoservices/).
* Other utility functions are located in
         [`com.siemens.pki.lightweightcmpra.util`](
  src/main/com/siemens/pki/lightweightcmpra/util/).
* The classes in [`com.siemens.pki.lightweightcmpra.client`](
          src/main/com/siemens/pki/lightweightcmpra/client/)
  and its sub-packages implement upstream interfaces
  towards the certificate authority (CA).
* The classes in [`com.siemens.pki.lightweightcmpra.server`](
            src/main/com/siemens/pki/lightweightcmpra/server/)
  and its sub packages implement downstream interfaces
  towards the end entity (EE).
* All packages described before are used by the classes in
         [`com.siemens.pki.lightweightcmpra.msgprocessing`](
  src/main/com/siemens/pki/lightweightcmpra/msgprocessing/)
  to implement the CMP (L)RA functionality.
* The package [`com.siemens.pki.lightweightcmpra.main`](
       src/main/com/siemens/pki/lightweightcmpra/main/)
  holds the startup code.
* The JUnit tests are located in
              [`com.siemens.pki.lightweightcmpra.test`](
  src/test/java/com/siemens/pki/lightweightcmpra/test/).
  To setup the RA for the tests the configuration files in
              [`com.siemens.pki.lightweightcmpra.test.config`](
  src/test/java/com/siemens/pki/lightweightcmpra/test/config)
  and the credentials in
              [`com.siemens.pki.lightweightcmpra.test.config.credentials`](
  src/test/java/com/siemens/pki/lightweightcmpra/test/config/credentials)
  are used.

A [README file](src/test/java/com/siemens/pki/lightweightcmpra/test/config/credentials/README.txt)
describes structure, purpose and use of the test credentials.

## Configuration

An annotated XML schema for the configuration can be found at
[src/schemes/Configuration.xsd](src/schemes/Configuration.xsd).
This file is also used to generate the XML parser located in
`com.siemens.pki.lightweightcmpra.config.xmlparser`.

## State of implementation

### Supported PKI management operations

This implementation provides only the (L)RA specific functional part
and behavior of all PKI management operations described in
[Lightweight CMP Profile](https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/).

All mandatory PKI management operations are supported:

* Section 4 - End Entity focused PKI management operations
  * Request a certificate from a new PKI with signature protection
  * Request to update an existing certificate with signature protection
  * Error reporting

* Section 5 - LRA and RA focused PKI management operations
  * Forward messages without changes
  * Forward messages with replaced protection
    and keeping the original proof-of-possession
  * Forward messages with replaced protection and raVerified
    as proof-of-possession
  * Error reporting

The Recommended PKI management operations mentioned below are also supported:

* Section 4 - End Entity focused PKI management operations
  * Request a certificate from a PKI with MAC protection
  * Revoke an own certificate.

* Section 5 - LRA and RA focused PKI management operations
  * Revoke another's entities certificate.

The Optional PKI management operations mentioned below are supported, too:

* Section 4 - End Entity focused PKI management operations
  * Request a certificate from a trusted PKI with signature protection
  * Request a certificate from a legacy PKI using a PKCS#10
    [[RFC 2986]](https://tools.ietf.org/html/rfc2986) request
  * Generate the key pair centrally at the PKI management entity
  * Handle delayed enrollment due to asynchronous message delivery
  * Some additional support messages

* Section 5 - LRA and RA focused PKI management operations
  * Forward messages with additional protection
  * Initiate delayed enrollment due to asynchronous message delivery

### CMP message transport variants

* HTTP transport
* HTTPS transport using certificates
* File-based transport
* CoAP transport

Due to a lack of public available implementations the
"HTTPS transport using shared secrets" is not implemented.

If your would like to do "Piggybacking on other reliable transport"
please have a look at the protocol implementations in
       [`com.siemens.pki.lightweightcmpra.client`](
src/main/com/siemens/pki/lightweightcmpra/client/) and
       [`com.siemens.pki.lightweightcmpra.server`](
src/main/com/siemens/pki/lightweightcmpra/server/).

On downstream interface side
your new protocol adapter has to call the message handler function of the
[BasicDownstream](src/main/com/siemens/pki/lightweightcmpra/msgprocessing/BasicDownstream.java)
instance for each incoming PKIMessage.
The new protocol adapter should be configured and set up in the constructor
of the BasicDownstream class.

On upstream interface side your new protocol adapter must implement
a message handler function.
The new protocol adapter should be configured and registered
in the constructor of the class
[RaUpstream](src/main/com/siemens/pki/lightweightcmpra/msgprocessing/RaUpstream.java).
If your new protocol adapter on upstream side is expected to support
delayed enrollment
it is recommended to inherit this function in some way from the base class
[OfflineClient](src/main/com/siemens/pki/lightweightcmpra/client/offline/OfflineClient.java).

## Other resources

An End Entity (EE) client implementation of the
[Lightweight CMP Profile](<https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/>)
based on OpenSSL can be found at
[CMPforOpenSSL](https://github.com/mpeylo/cmpossl/wiki).
The [openssl-cmp manual page](https://github.com/openssl/openssl/blob/master/doc/man1/openssl-cmp.pod.in)
gives an overview of the functionality.
