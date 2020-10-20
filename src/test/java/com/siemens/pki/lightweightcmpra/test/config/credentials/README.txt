This directory holds
the credentials needed for the tests located in com.siemens.pki.lightweightcmpra.test.
The password for each of the key stores is "Password".
The credentials (certificate and private key of end nodes) are stored in various formats.

NEVER USE THESE CREDENTIALS IN A PRODUCTIVE SYSTEM!

CMP credentials of the CA mockup:
	CMP_CA_Chain.pem
	CMP_CA_Keystore.jks
	CMP_CA_Keystore.p12
	CMP_CA_Root.pem

CMP credentials of the EE mockup:
	CMP_EE_Chain.pem
	CMP_EE_Keystore.jks
	CMP_EE_Keystore.p12
	CMP_EE_Root.pem

CMP credentials of the (L)RA under test used at downstream interface towards the EE mockup:
	CMP_LRA_DOWNSTREAM_Chain.pem
	CMP_LRA_DOWNSTREAM_Keystore.jks
	CMP_LRA_DOWNSTREAM_Keystore.p12

CMP credentials of the (L)RA under test used at upstream interface towards the CA mockup:
	CMP_LRA_UPSTREAM_Chain.pem
	CMP_LRA_UPSTREAM_Keystore.jks
	CMP_LRA_UPSTREAM_Keystore.p12

Credentials used by the CA mock to generate a new certificate for the EE:
	ENROLL_Chain.pem
	ENROLL_Keystore.jks
	ENROLL_Keystore.p12
	ENROLL_Root.pem

Certificates used for the support message tests:
	newWithNew.pem
	newWithOld.pem
	oldWithNew.pem
