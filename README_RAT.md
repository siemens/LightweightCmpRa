# Support for Remote Attestation in Certificate Signing Requests (CSRs)

This branch supports the internet drafts [Use of Remote Attestation with Certification Signing Requests](https://datatracker.ietf.org/doc/draft-ietf-lamps-csr-attestation/) and [Nonce-based Freshness for Remote Attestation in Certificate Signing Requests (CSRs) for the Certification Management Protocol (CMP) and for Enrollment over Secure Transport (EST) draft-ietf-lamps-attestation-freshness](https://datatracker.ietf.org/doc/draft-ietf-lamps-attestation-freshness/).

# Design

To satisfy the configuration interface extensions of the [CmpRaComponent](https://code.siemens.com/ct-rda-cst-ses-de/remote-attestation/base-functionality/CmpRaComponent) few configuration items are added.

# Building from scratch
```bash
git clone  git@code.siemens.com:ct-rda-cst-ses-de/remote-attestation/base-functionality/CmpRaComponent.git
git clone  git@code.siemens.com:ct-rda-cst-ses-de/remote-attestation/base-functionality/lightweightcmpra.git 

cd CmpRaComponent/
git checkout RAT_integration
mvn clean install -Ddependency-check.skip=true -Dgpg.skip -DskipTests
cd ..

cd lightweightcmpra/
git checkout RAT_integration
mvn clean install -Ddependency-check.skip=true -Dgpg.skip -DskipTests
cd ..
```

# Mix runtime environment together
```bash
cd lightweightcmpra
mkdir run
cd run
cp -r ../target/*.jar ../target/lib .
cp -r ../src/test/java/com/siemens/pki/lightweightcmpra/test/config/* .
```

# Launch Mock CA

```bash
java -cp LightweightCmpRa-4.0.1_rat-SNAPSHOT.jar:LightweightCmpRa-4.0.1_rat-SNAPSHOT-tests.jar  \
	com.siemens.pki.lightweightcmpra.test.framework.CmpCaMock \
	. http://localhost:7000/ca credentials/ENROLL_Keystore.p12 credentials/CMP_CA_Keystore.p12&
```

# Launch RA

```bash
java -jar LightweightCmpRa-4.0.1_rat-SNAPSHOT.jar EnrollmentConfigWithRAT.yaml&
```

# Alternative: Launch RA with message dump

```bash
mkdir dump
java -Ddumpdir=dump -jar LightweightCmpRa-4.0.1_rat-SNAPSHOT.jar EnrollmentConfigWithRAT.yaml&
```

# Launch Java Client

## RAT Test case

To execute the TC the verifier REST endpoint [`com.siemens.pki.verifieradapter.veraison.rest.RestConfig.DEFAULT_VERIFIER_BASE_PATH`](src/main/java/com/siemens/pki/verifieradapter/veraison/rest/RestConfig.java) in the CmpRaComponent project needs to be adapted to the current network setup.

```bash
mkdir -p Results
java -cp LightweightCmpRa-4.0.1_rat-SNAPSHOT.jar \
	com.siemens.pki.lightweightcmpclient.main.CliCmpClient \
	--configfile ClientEnrollmentConfigWithRAT.yaml \
	--enroll Results/EnrollmentResult.pem \
	--enrollmentChain Results/EnrollmentChain.pem 
```




 
 
