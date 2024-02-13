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
java -cp LightweightCmpRa-4.1.0_ALEX.jar:LightweightCmpRa-4.1.0_ALEX-tests.jar  \
	com.siemens.pki.lightweightcmpra.test.framework.CmpCaMock \
	. http://localhost:7000/ca credentials/ENROLL_Keystore.p12 credentials/CMP_CA_Keystore.p12&
```

# Launch RA

```bash
java -jar LightweightCmpRa-4.1.0_ALEX.jar EnrollmentConfigWithHttpAndSignature.yaml&
```

# Alternative: Launch RA with message dump

```bash
mkdir dump
java -Ddumpdir=dump -jar LightweightCmpRa-4.1.0_ALEX.jar EnrollmentConfigWithHttpAndSignature.yaml&
```

# Launch Java Client

```bash
mkdir -p Results
java -cp LightweightCmpRa-4.1.0_ALEX.jar \
	com.siemens.pki.lightweightcmpclient.main.CliCmpClient \
	--configfile ClientEnrollmentConfigWithDifferentKeys.yaml \
	--enroll Results/EnrollmentResult.pem \
	--enrollmentChain Results/EnrollmentChain.pem \
	--certProfile ML-KEM-512
```
	
	
	
	

 






 
 
