<!--
Copyright (c) 2019 Siemens AG
Licensed under the Apache License, Version 2.0
SPDX-License-Identifier: Apache-2.0
-->

# Lightweight CMP RA

This repository provides a CLI-based Registration Authority application
for demonstration and test purposes that implements the
[Lightweight CMP Profile](https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/)
for CMP [[RFC 4210]](https://tools.ietf.org/html/rfc4210).
As implementation of the core CMP Registration Authority (RA) functions the
[generic CMP RA component](https://github.com/siemens/cmp-ra-component) is used.

## License

This software is licensed under the Apache License, Version 2.0.

# Disclaimer

This prototypical code does not claim to have production quality
but is meant for exploration and PoC use of the Lightweight CMP Profile.
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

### Required build tools and environment

* The *Java SE Development Kit (JDK)*.
  The Lightweight CMP RA is now developed using JDK 11.
  It can be found at
  <https://www.oracle.com/java/technologies/downloads/#java11>.
* The *Apache Maven tool*.
  For details, documentation, and download see <http://maven.apache.org/>.
* The *GIT version control system*.
  For details, documentation, and download see <http://git-scm.com/>.

On a Debian-like system the packages can be installed, e.g., using

```
sudo apt install adoptopenjdk-11-hotspot maven git
```

The code has been adapted to work with Java version 1.11 (at least).
If also other versions of Java are installed on your system
make sure that a suitable version is active, e.g., like this:
```
sudo update-alternatives --config java
```
You can verify the selected version using
```
java -version
```

### Download and install the dependency: the generic CMP RA component

This implementation uses the
[generic CMP RA component](https://github.com/siemens/cmp-ra-component)
for CMP-related functions cryptographic operations.
The component needs to be installed into the local maven repository:

```bash
git clone https://github.com/siemens/cmp-ra-component.git
cd cmp-ra-component
mvn clean install -DskipTests=true
cd ..
```

## Download the sources

```bash
git clone https://github.com/siemens/LightweightCmpRa.git
cd LightweightCmpRa
```

## Build the Lightweight CMP RA

```bash
mvn clean install
```

This includes running unit tests, which may also be invoked explicitly by

```bash
mvn test
```

## Running the RA

Example YAML configuration files can be found at
[src/test/java/com/siemens/pki/lightweightcmpra/test/config](
 src/test/java/com/siemens/pki/lightweightcmpra/test/config)
and after installation also at `target/test-classes`.

The RA can be started with one or more *YAML configuration Files*
as command line argument.
Each *YAML configuration File* describes one RA instance to launch.

```bash
cd target/test-classes
java -jar ../LightweightCmpRa-2.0.0.jar <XML/YAML/JSON configuration File>
```

If you use your IDE (e.g. Eclipse) to generate a "Runnable JAR file" it is recommended to have
the required libraries in a subfolder and not packed with the generate JAR file. 

# Software architecture

## External components

This implementation uses the
[generic CMP RA component](https://github.com/siemens/cmp-ra-component)
for CMP-related functions cryptographic operations.

The [Simple Logging Facade for Java (SLF4J)](http://www.slf4j.org/)
serves as a simple facade or abstraction for various logging frameworks
(e.g., `java.util.logging`, `logback`, `log4j`).
If the
[SimpleLogger](http://www.slf4j.org/apidocs/org/slf4j/impl/SimpleLogger.html)
is used, full logging can be enabled by giving
`-Dorg.slf4j.simpleLogger.log.com.siemens=debug` as first command line option.

The [Eclipse Californium](https://www.eclipse.org/californium/)
is used for CoAP support.

The [JUnit testing framework](https://junit.org/)
is used for implementing some tests.

## Internal structure

* The Java package [`com.siemens.pki.lightweightcmpra.configuration`](
               src/main/java/com/siemens/pki/lightweightcmpra/configuration/)
  holds all classes and functions needed for YAML configuration parsing.

* The classes in [`com.siemens.pki.lightweightcmpra.downstream`](
            src/main/java/com/siemens/pki/lightweightcmpra/server/)
  and its sub packages implement downstream transport
  protocol adapters towards the end entity (EE).
* The package [`com.siemens.pki.lightweightcmpra.downstream.offline`](
       src/main/java/com/siemens/pki/lightweightcmpra/downstream/offline)
  holds all classes and functions needed to implement offline downstream
  transport protocol adapters (e.g. to file system).
* The package [`com.siemens.pki.lightweightcmpra.downstream.online`](
       src/main/java/com/siemens/pki/lightweightcmpra/downstream/online)
  holds all classes and functions needed to implement online downstream
  transport protocol adapters (e.g. to CoAP and HTTP(s)).

* The classes in [`com.siemens.pki.lightweightcmpra.upstream`](
          src/main/java/com/siemens/pki/lightweightcmpra/upstream/)
  and its sub-packages implement upstream transport protocol adapters
  towards the certificate authority (CA).
* The package [`com.siemens.pki.lightweightcmpra.upstream.offline`](
       src/main/java/com/siemens/pki/lightweightcmpra/upstream/offline)
  holds all classes and functions needed to implement offline upstream
  transport protocol adapters (e.g. to file system).
* The package [`com.siemens.pki.lightweightcmpra.upstream.online`](
       src/main/java/com/siemens/pki/lightweightcmpra/upstream/online)
  holds all classes and functions needed to implement online upstream transport
  protocol adapters (e.g. to HTTP(s)).
* Some utility functions are located in
         [`com.siemens.pki.lightweightcmpra.util`](
  src/main/java/com/siemens/pki/lightweightcmpra/util/).
* The package [`com.siemens.pki.lightweightcmpra.main`](
       src/main/java/com/siemens/pki/lightweightcmpra/main/)
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

A [README file](/doc/config/README.md)
explains the YAML configuration file structure.

### CMP message transport variants

* HTTP transport
* HTTPS transport using certificates
* File-based transport
* CoAP transport

Due to a lack of public available implementations the
"HTTPS transport using shared secrets" is not implemented.

## Other resources

An End Entity (EE) client implementation of the
[Lightweight CMP Profile](<https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/>)
based on OpenSSL can be found at
[CMPforOpenSSL](https://github.com/mpeylo/cmpossl/wiki).
The [openssl-cmp manual page](https://github.com/openssl/openssl/blob/master/doc/man1/openssl-cmp.pod.in)
gives an overview of the functionality.

## Interoperability

Details about with other CMP implementations and reference message flows can be
found in the [Interoperability document](/doc/interop/Interoperability.md)

## Known issues

With JDK 11, revocation checking has some issues:
* A CRL provided as CRLDP extension is not always used in path validation
  for CMP and TLS trust chains.
* An OCSP AIA extension is not always used in path validation
  for TLS trust chains.
