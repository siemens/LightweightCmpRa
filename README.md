<!--
Copyright (c) 2019 - 2024 Siemens AG
-->

# Lightweight CMP RA and CMP Client CLI applications

This repository provides CLI-based Registration Authority (RA) and CMP client
Java applications for demonstration and test purposes.\
It offers CMP features according to RFCs 4210 and 9480 
according to the [Lightweight CMP Profile](
https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/).\
It uses the [generic CMP RA component](https://github.com/siemens/cmp-ra-component)
as an implementation of the core CMP features.

## License

This software is licensed under the Apache License, Version 2.0.

SPDX-License-Identifier: Apache-2.0

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
mvn clean install -DskipTests=true -Dgpg.skip
cd ..
```

## Download the sources

```bash
git clone https://github.com/siemens/LightweightCmpRa.git
cd LightweightCmpRa
```

## Build the software

```bash
mvn clean install
```

This includes running unit tests, which may also be invoked explicitly by

```bash
mvn test
```

## Updating the build

In case the software has already been installed before,
for updating it is sufficient to execute

```bash
git pull
mvn clean install -DskipTests=true -Dgpg.skip
```
in both directories.

## Running the RA

Example YAML configuration files can be found at
[src/test/java/com/siemens/pki/lightweightcmpra/test/config](
 src/test/java/com/siemens/pki/lightweightcmpra/test/config)
and after installation also at `target/test-classes`.

The RA can be started with one or more *YAML configuration files*
as command line argument.
Each *YAML configuration file* describes one RA instance to launch.

```bash
cd target/test-classes
java -jar ../LightweightCmpRa-x.y.z.jar <YAML/JSON configuration file>
```
`x`, `y`, and `z` are the three parts of the version number.

If you use your IDE (e.g. Eclipse) to generate a "Runnable JAR file" it is recommended to have
the required libraries in a subfolder and not packed with the generate JAR file.

# RA Software architecture

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

Due to a lack of publicly available implementations, the
"HTTPS transport using shared secrets" is not implemented.

## Interoperability

Details about with other CMP implementations and reference message flows can be
found in the [Interoperability document](/doc/interop/Interoperability.md)

## Known issues

With JDK 11, revocation checking has some issues:
* A CRL provided as CRLDP extension is not always used in path validation
  for CMP and TLS trust chains.
* An OCSP AIA extension is not always used in path validation
  for TLS trust chains.


# Lightweight CMP client CLI application

Besides and RA, this repository provides a CLI-based CMP client application,
which uses part of
the [generic CMP RA component](https://github.com/siemens/cmp-ra-component)
as an implementation of the core CMP CLient (EE) features.

## Running the CLI Client

The CLI client needs a configuration file
given with a `-c` or `--configfile` option.

It can invoke the following CMP transactions.
* certificate enrollment (option `--enroll`)
* certificate revocation using issuer and serial number from configuration (option `--revoke`)
* certificate revocation for a given certificate (option `--revokecert`)
* get CA certificates (option `--getCaCertificates`)
* get a root CA certificate update  (option `--getRootCaCertificateUpdate`)
* get certificate request template (option `--getCertificateRequestTemplate`)
* CRL retrieval (option `--getCrls`)

Details on the available CLI options are described below.

Note that both the `--configfile` and `--certProfile` options can be used
to distinguish between the following.
* different CMP client credentials
* different CMP servers and access points
* different types of enrollement (i.e., IR, CR, and KUR)
* different types of certificates to be enrolled or revoked
  or to get revocation request templates or CRLs for
* different CAs to get certificates or root certificate updates for

```
usage: java -jar path/to/CmpClient.jar
 -h,--help                                  print help and exit.
 -e,--enroll <arg>                          invoke a certificate
                                            enrollment transaction; <arg>
                                            is the file path and name
                                            where the newly
                                            enrolled certificate and the
                                            corresponding private key will
                                            be written in PEM format,
 -R,--revoke                                invoke a revocation transaction
                                            with data from configuration
 -r,--revokecert <arg>                      invoke a revocation.
                                            transaction; <arg> is the file
                                            path and name of certificate
                                            to revoke in PEM format
 -a,--getCaCertificates <arg>               invoke a Get CA certificates
                                            GENM request, <arg> is the
                                            file path and name of certificates
                                            to write in PEM format.
 -t,--getCertificateRequestTemplate <arg>   invoke a Get certificate
                                            request template GENM request,
                                            <arg> is the file path and
                                            name of the request template
                                            to write in DER format.
 -u,--getRootCaCertificateUpdate [<arg>]    invoke a Get root CA
                                            certificate update GENM
                                            request; the optional <arg> is the
                                            file path and name of
                                            certificate to get an update
                                            for in PEM format.
 -l,--getCrls <arg>                         invoke a CRL Update Retrieval
                                            GENM request; <arg> is the
                                            file path and name of CRLs to
                                            write in PEM format.
 -c,--configfile <arg>                      <arg> is the path and name of
                                            the CMP client configuration
                                            file to use;
                                            this option is mandatory.
 -C,--configroot <arg>                      configuration root path
 -p,--certProfile <arg>                     certProfile to use; optional
                                            for all client commands.
 -n,--enrollmentChain <arg>                 <arg> is the file path and
                                            name to write the newly
                                            enrolled certificate and its
                                            chain (excluding the root
                                            certifiate) in PEM format.
                                            This option can be used in
                                            conjunction with the -e option.
 -k,--enrollmentKeystore <arg>              <arg> is the file path and
                                            name to write the enrolled
                                            certificate, chain, and
                                            private key in PKCS#12 format.
                                            This option can be used in
                                            conjunction with the -e option.
 -w,--enrollmentKeystorePassword <arg>      <arg> is the password to be
                                            used for encrypting the
                                            enrollmentKeystore.
                                            This option can be used in
                                            conjunction with the -k option.
 -W,--NewWithNew <arg>                      <arg> is the file path and
                                            name of the new root CA
                                            certificate to write in PEM format.
                                            This option can be used in
                                            conjunction with the -u option.
 -N,--NewWithOld <arg>                      <arg> is the path and name of
                                            the file to write any received
                                            new root CA public key signed
                                            with the old private root CA key.
                                            This option can be used in
                                            conjunction with the -u option.
 -O,--OldWithNew <arg>                      <arg> is the path and name of
                                            the file to write any received
                                            certificate containing the old
                                            root CA public key signed with
                                            the new private root CA key.
                                            This option can be used in
                                            conjunction with the -u option.
 -S,--serial <arg>                          <arg> is the serial number of
                                            the certificate to revoke with
                                            the -R option.
 -I,--issuer <arg>                          <arg> can be the issuer of the
                                            certificate to revoke with the
                                            -R option; <arg> can
                                            also be the issuer in
                                            CRLSource to consult in
                                            conjunction with the -l option.
 -D,--dpn <arg>                             <arg> is the
                                            DistributionPointName in
                                            CRLSource to consult. This
                                            option can be used in
                                            conjunction with the -l option.
 -U,--thisUpdate <arg>                      <arg> is the thisUpdate time
                                            in CRLStatus of the most
                                            recent CRL knowns by the client;
                                            format is "yyyy-MM-dd" or "now".
                                            This option can be used in
                                            conjunction with the -l option.
 -L,--oldCRL <arg>                          <arg> is the CRL for which an
                                            update is requested; this is an
                                            alternative to using the --issuer,
                                            --dpn, and --thisUpdate options.
                                            This   option can be used in
                                            conjunction with the -l option.

```

## Configuration

The lower part of the [configuration README file](/doc/config/README.md)
explains the YAML configuration file structure.


## Related resources

An End Entity (EE) client implementation of the
[Lightweight CMP Profile](<https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/>)
based on OpenSSL with an high-level C API and a CLI is provided by the
[generic CMP client](https://github.com/siemens/gencmpclient).
The [openssl-cmp manual page](https://github.com/openssl/openssl/blob/master/doc/man1/openssl-cmp.pod.in)
gives an overview of the functionality from CLI usage perspective.


