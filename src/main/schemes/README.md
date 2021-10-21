# Configuration of the Lightweight CMP RA
The **Lightweight CMP RA** behavior is specified in an configuration file. Path and name of this configuration file
is the first command line parameter needed to start the **Lightweight CMP RA**.
This configuration file is structured in many hierarchical entity sections holding attributes and sub entity sections.
The configuration file can be written in XML, YAML or JSON

So the structure coulds looks like

```xml
<toplevelentity attribute1="value 1" attribute2="Value2">
	<subentity1 attribute3="value 3" attribute4="Value4">
	... more nested entities
	</subentity1>
	<subentity2 attribute5="value5" attribute6="Value 6"/>
</toplevelentity>

```

or

```yaml
toplevelentity:
  attribute1: "value 1" 
  attribute2: Value2
    subentity1:
      attribute3: "value 3" 
      attribute4: Value4

# ... more nested entities

    subentity2:
      attribute5: value5
      attribute6: "Value 6"
```

or 

```json
"toplevelentity": {
   "attribute1" : "value 1",
   "attribute2" : "Value2",
	"subentity1" : {
	   "attribute3" : "value 3",
	   "attribute4" : "Value4",
	  
	  "___COMMENT___":  "more nested entities"
	  
	},
	"subentity2" : {
	   "attribute5" : "value5",
	   "attribute6" : "Value 6"
	}
}

```

The configuration file must contain **exactly one** [Configuration entity](#the-configuration-entity).
In a production environment the integrity of this configuration file must be protected by external measures.

Examples can be found in the [Test Configuration](/src/test/java/com/siemens/pki/lightweightcmpra/test/config).

## The Configuration entity

The **Configuration entity** and its sub entities describes the configuration and behavior of one **Lightweight CMP RA** instance.
It contains a sequence of **zero or more**
- [RaConfiguration entities](#the-raconfiguration-entity),
- [ServiceConfiguration entities](#the-serviceconfiguration-entity) and
- [RestHttpServer entities](#the-restservice-entity).

The **Configuration entity** has no attributes.

## The RaConfiguration entity

The **RaConfiguration entity** describes the configuration and behavior of one CMP (L)RA instance as specified in the [Lightweight CMP Profile](https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/). A (L)RA instance receives certificate enrollment requests by its **Downstream** interface, forwards it to the **Upstream** interface and validates the enrolled certificate against the **EnrollmentCredentials**. The **EnrollmentCredentials** are also used to complete the certificate chain returned in the **extraCerts** of the enrollment response.

The **RaConfiguration entity** contains
- **one** [Upstream entity](#the-upstream-entity),
- **one** [EnrollmentCredentials entity](#the-enrollmentcredentials-entity) and 
- **one** [Downstream entity](#the-downstream-entity).

The **RaConfiguration entity** has no attributes.

## The Upstream entity
The **Upstream entity** describes configuration and behavior of the **Upstream** interface towards the CA. It contains
- **one** [CmpCredentials entity](#the-cmpcredentials-entity) describing the protection configuration used for outgoing requests and incoming responses,
- **one optional** [NestedEndpointCredentials entity](#the-nestedendpointcredentials-entity) if outgoing requests should be wrapped in a nested message and
- **one** client configuration describing the underlaying transport mechanism used to communicate with the next upstream RA or CA. The client configuration can be
    - **one** [CmpHttpClient entity](#the-cmphttpclient-entity) or
    - **one** [OfflineFileClient entity](#the-offlinefileclient-entity).

The **Upstream entity** has the optional boolean attribute **enforceRaVerified** which can have the value *true* or *false*. If **enforceRaVerified** is *true* the proof of possession will be forced to **raVerified** for all outgoing enrollment requests.

## The EnrollmentCredentials entity
The **EnrollmentCredentials entity** specifies the credentials used to validate an enrolled certificate and to calculate the additional certificates in the extraCerts field of IP, CP and KUP. All attributes and entities of the 
[Trust Credentials Type](#the-trust-credentials-type) can be used here.

## The Downstream entity
The **Downstream entity** describes interfaces towards the EE sharing the same CmpCredentials.
It contains
- **one** [CmpCredentials entity](#the-cmpcredentials-entity) describing the protection configuration used for outgoing requests and incoming responses,
- **one optional** [NestedEndpointCredentials entity](#the-nestedendpointcredentials-entity) if incoming nested messages should be unwrapped,
- **one optional** [CentralKeyGeneration entity](#the-centralkeygeneration-entry) if central key generation should be supported,
- **one** server configuration describing the underlaying transport mechanism used to communicate with the next downstream RA or EE. The server configuration can be
    - **one** [CmpHttpServer entry](#the-cmphttpserver-entry) or
    - **one** [CoapServer entry](#the-coapserver-entry) or
    - **one** [MessageHandler entry](#the-messagehandler-entry) or
    - **one** [OfflineFileServer entry](#the-offlinefileserver-entry).

The **Downstream entity** has the mandatory boolean attribute **AcceptRaVerified** which can have the value *true* or *false*. If **AcceptRaVerified** is *false* a proof of possession of **raVerified** is not acceptable for incoming enrollment requests.

## The CmpHttpServer entry
The **CmpHttpServer entity** describes a HTTP(S) server interface used for CMP message reception and response as 
specified in [RFC 6712](https://www.rfc-editor.org/rfc/rfc6712.txt) towards the EE.
If HTTP over TLS (HTTPS) is used this entity must contain **one** [TlsConfig entity](#the-tlsconfig-entity).
The **CmpHttpServer entity** has the mandatory attribute **ServingUrl**. The **ServingUrl** specifies the address of the provided HTTP or HTTPs server endpoint, e.g. *https://0.0.0.0/path/to/ra/endpoint*. The hostname or IP part will be ignored.

## The CoapServer entry
The **CoapServer entry** describes a CoAP endpoint as described in [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252.txt).
It has one mandatory attribute **path**. The **path** attribute describes the CoAP path to be served.

## The MessageHandler entry
The **MessageHandler entry** sets up an internal message handler. This is an extension point to attach further transport protocols.
The **MessageHandler entry** has the mandatory attribute **Id**. The attribute **Id** can be used for API access of the message handler.

## The OfflineFileServer entry
The **OfflineFileServer entity** describes a file based client interface used for CMP message reception and response towards the EE. This entity has the mandatory attributes described below:
- The attribute **InputDirectory** describes the relative or absolute path to a directory which is scanned cyclicly for files containing a DER encoded CMP message. Such messages are processed in the same way as other incoming messages.
- The attribute **OutputDirectory** describes the relative or absolute path to a directory used to write outgoing DER encoded CMP messages.

## The CentralKeyGeneration entry
If the **CentralKeyGeneration entry** is present central key generation is supported by this RA.
It has two mandatory attributes needed to describe own credentials used for key transport or encryption.
- The attribute **KeyStorePath** holds a relative or absolute filename of a password protected Java Keystore file (JKS) or PKCS#12 file containing the own private key and certificate. 
- The attribute **KeyStorePassword** contains a plain-text password required to open the Keystore.

## The CmpHttpClient entity

The **CmpHttpClient entity** describes a HTTP(S) client interface used for CMP message forwarding and reception as 
specified in [RFC 6712](https://www.rfc-editor.org/rfc/rfc6712.txt) towards the CA.
If HTTP over TLS (HTTPS) is used this entity must contain **one** [TlsConfig entity](#the-tlsconfig-entity).
The **CmpHttpClient entity** has the mandatory attribute **ServerUrl**. The **ServerUrl** specifies the address of an HTTP or HTTPs endpoint of the next upstream server, e.g. *https://myca.domain.com/path/to/ca/endpoint* .

## The TlsConfig entity 

The **TlsConfig entity** describes the credentials needed to establish a TLS connection (optional with mutual authentication). 
All attributes and sub entities of the [Mutual Certificate Credentials Type](#the-mutual-certificate-credentials-type)
can be used. Additional the **TlsConfig entity** has the optional attribute **EnableHostVerification** which can have the value *true* or *false*. If **EnableHostVerification** is set to false, the TLS client will skip the validation of the TLS server FQDN(Full Qualified Domain Name).

 
## The Mutual Certificate Credentials Type
The **Mutual Certificate Credentials Type** is used for different entities in the configuration file. 
This type holds the attributes and sub entities needed to describe the credentials required to provide certificate-based
mutual authentication. All attributes and sub entities of the [Trust Credentials Type](#the-trust-credentials-type)
can be used to describe the authentication of a trusted TLS peer or the protection of a received CMP message.
The **Mutual Certificate Credentials Type** has two mandatory attributes needed to describe own credentials used for CMP protection, authentication, signing or encryption or to provide TLS authentication to the peer.
- The attribute **KeyStorePath** holds a relative or absolute filename of a password protected Java Keystore file (JKS) or PKCS#12 file containing the own private key and certificate. 
- The attribute **KeyStorePassword** contains a plain-text password required to open the Keystore.


## The Trust Credentials Type
The **Trust Credentials Type** is used for different entities and types in the configuration file. 
This type holds the attributes and sub entities needed to describe credentials required to provide certificate-based authentication and trust.
It may contain 
- **zero or more** [CrlFile entities](#the-crlfile-entity),
- **zero or more** [CrlUrl entities](#the-crlurl-entity) and 
- **zero or more** [MatchingPeerCertificateSubject entities](#the-matchingpeercertificatesubject-entity).

The **Trust Credentials Type** has optional and mandatory attributes described below:
- The mandatory attribute **TrustStorePath** is a relative or absolute filename of a password protected Java Keystore file (JKS), a PKCS#12 file or 
  a file containing concatinated certificates in PEM format describing all trusted certificates.
- If a JKS or PKCS#12 file is used the **TrustStorePassword** attribute holds the Password to open the truststore.
- The optional attribute **DefaultOcspResponder** specifies the URL of the default OCSP responder, which is
  contacted when no AIA extension is provided in the certificate.
- The optional boolean attribute **EnableCrlCheck** must be set to *true* if CRL based revocation checking should be enabled.
- The optional boolean attribute **EnableCRLDistPoints** must be set to *true* if the if CRL Distribution Points extension should be used in CRL based revocation checking.
- The optional boolean attribute **EnableNoFallback** must be set to *true* if the the fallback mechanism is disables in CRL based revocation checking. 
- The optional boolean attribute **EnableOcspCheck** must be set to *true* if OCSP based revocation checking should be preferred and enabled.
- The optional boolean attribute **EnableOnlyEndEntityCheck** must be set to *true* if only the certificate status of the end
  entity should be checked for revocation status.
- The optional boolean attribute **EnablePreferCRLs** must be set to *true* if CRL based revocation checking should be preferred.
- If the optional boolean attribute **EnableSoftFail** is set to *true* the revocation check is allowed to succeed to succeed if the
  revocation status cannot be determined for the following reasons: The CRL or OCSP response cannot be obtained because of a
  network error.
- If the optional boolean attribute **EnableKeyUsageCheck** is set to *false* the check of key usage digitalSignature in the end certificate is disabled.

## The CrlFile entity
The **CrlFile entity** describes the location of a CRL file used for revocation checking. It has the mandatory attribute **path** holding the relative or absolute name of a file containing the CRL. 

## The CrlUrl entity
The **CrlUrl entity** describes a URL to fetch a CRL used for revocation checking. It has the mandatory attribute **uri** holding the URL to access the CRL. 

## The MatchingPeerCertificateSubject entity
The **MatchingPeerCertificateSubject entity** holds a regular expression string. If the subject of the peer end certificate does not match this expression then the peer certificate is not accepted. 

## The OfflineFileClient entity
The **OfflineFileClient entity** describes a file based client interface used for CMP message forwarding and reception towards the CA. This entity has the mandatory attributes described below:
- The attribute **OutputDirectory** describes the relative or absolute path to a directory used to write outgoing DER encoded CMP messages.
- The attribute **InputDirectory** describes the relative or absolute path to a directory which is scanned cyclicly for files containing a DER encoded CMP message. Such messages are processed in the same way as other incoming messages.
- The numeric attribute **checkAfterTime** describes the time in seconds which should be used to fill the checkAfter field in the PollRepContent.

## The CmpCredentials entity
The **CmpCredentials entity** describes the Credentials to build and check CMP protection.
This entity holds the credentials required to protect outgoing CMP messages and to validate the protection of incoming CMP messages.

The **CmpCredentials entity** contains 
- **one** [in entity](#the-in-entity) describing the protection validation of incoming messages and 
- **one** [out entity](#the-out-entity) describing the protection to apply for outgoing messages.

## The in entity
The **in entity** describes how to validate the incoming protection. It contains 
- **zero or one** [SignatureBased entity (in)](#the-signaturebased-entity-in) and
- **zero or one** [PasswordBased entity (in)](#the-passwordbased-entity-in).

The **in entity** contains two attributes:
- If the boolean attribute **enforceProtection** is set to false the received message is allowed to be unproteced.
- If the numeric attribute **allowedTimeDeviationInSeconds** is set it specifies the allowed positive or negative offset in the message time in relation to the local time.

## The SignatureBased entity (in)
The **SignatureBased entity** describes the validation of a signature based protection. All attributes and entities of the 
[Trust Credentials Type](#the-trust-credentials-type) can be used here.
This entity has an additional optional boolean attribute **cacheExtraCerts**. If **cacheExtraCerts** is set to *true*, 
received extraCerts related to a specific transactionID are cached and later re-used, if next received message comes without extraCerts.

## The PasswordBased entity (in)
The **PasswordBased entity** describes the validation of a password based protection. The mandatory attribute **Password** specifies the expected password. If the optional attribute **Username** is given, the received senderKID must be equal to this attribute value.

## The out entity
The **out entity** describes the protection to apply to outgoing messages. This entity can have 
- a [SignatureBased entity (out)](#the-signaturebased-entity-out) or 
- a [PasswordBased entity (out)](#the-passwordbased-entity-out).

It has the two optional attributes **suppressRedundantExtraCerts** and **reprotectMode**.
If the boolean attribute **suppressRedundantExtraCerts** is set to *true* the same extraCerts certificate is not sent
twice in a message flow related to a specific transactionID.

The optional attribute **reprotectMode** controls the protection behaviour:
- If the attribute value is set to *reprotect* the outgoing message will be reprotected in any case. This is the default behavior.
- If the attribute value is set to *forward* an existing protection of a forwarded message is preserved, if possible
- If the attribute value is set to *strip* any protection is removed from the outgoing message 

## The SignatureBased entity (out)
The **SignatureBased entity** describes the signature based protection for outgoing messages. It has two mandatory attributes:
- The attribute **KeyStorePath** holds a relative or absolute filename of a password protected Java Keystore file (JKS) or PKCS#12 file containing the own private key and certificate. 
- The attribute **KeyStorePassword** contains a plain-text password required to open the Keystore.

## The PasswordBased entity (out)

The **PasswordBased entity** describes the password based protection for outgoing messages. The mandatory attribute **Password** specifies the password to use. If the optional attribute **Username** is given, the sent senderKID in the message is set to this value.

## The NestedEndpointCredentials entity

If the **NestedEndpointCredentials entity** is present outgoing messages are wrapped in nested messages and incoming nested messages are unwrapped.
It contains 
- **one** [in entity](#the-in-entity) describing the protection validation of incoming nested messages and 
- **one** [out entity](#the-out-entity) describing the protection to apply for outgoing nested messages.

The **NestedEndpointCredentials entity** has one mandatory attribute **Recipient**. The **Recipient** attribute
specifies the recipient for outgoing messages.

## The ServiceConfiguration entity

The **ServiceConfiguration entity** describes a service responding to general messages.
It contains 
- **one** [Downstream entity](#the-downstream-entity) describing the interface for receiving and responding messages and 
- **one or more** [Response entities](#the-response-entity) describing the responses to return.

## The Response entity

The **Response entity** describes one specific general message response (genp). The optional attribute **servingOid** specifies the OID to respond to. If not provided, the defaults (id-it-caCerts, id-it-rootCaKeyUpdate, id-it-certReqTemplate) are used.
The **Response entity** contains 
- **one** [SequenceOfCMPCertificate entity](#the-sequenceofcmpcertificate-entity) or
- **one** [CAKeyUpdAnnContent entity](#the-cakeyupdanncontent-entity) or
- **one** [AnyAsn1Content entity](#the-anyasn1content-entity)

## The SequenceOfCMPCertificate entity

The **SequenceOfCMPCertificate entity** describes a service responding a generic message response containing a SEQUENCE OF CMPCerticates. 
More details are described in 
the [Lightweight CMP Profile](https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/), chapter "4.3.1. Get CA certificates".
The mandatory attribute **sourceFile** specifies the absolute or relative path and name of a file containing the certificates to return.

## The CAKeyUpdAnnContent entity

The service described in **CAKeyUpdAnnContent entity** returns up to 3 certificates as partly tagged SEQUENCE members. 
More details are described in 
the [Lightweight CMP Profile](https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/), chapter "4.3.2. Get root CA certificate update".
The optional attributes **oldWithNew**, **newWithOld** and **newWithNew** specifies the absolute or relative path and name of a file containing each 
one certificate.

## The AnyAsn1Content entity

The service described in **AnyAsn1Content entity** can return any possible ASN.1 value. 
It can be used to implement the PKI management operation described in 
the [Lightweight CMP Profile](https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/), chapter "4.3.3. Get certificate request template".
The mandatory attribute **sourceFile** specifies the absolute or relative path and name of a file containing the binary encoded ASN.1 value to return.

## The RestService entity

The **RestService entity** specifies a REST service for certificate revocation.
It contains 
- **one** [Upstream entity](#the-upstream-entity) describing the interface towards the CA and
- **one** [RestHttpServer entity](#the-resthttpserver-entity).

## The RestHttpServer entity

The **RestHttpServer entity** describes a HTTP(S) server interface providing a REST service.
If HTTP over TLS (HTTPS) is used this entity must contain **one** [TlsConfig entity](#the-tlsconfig-entity).
The **RestHttpServer entity** has the mandatory attribute **ServingUrl**. The **ServingUrl** specifies the address of the provided HTTP or HTTPs server endpoint, e.g. *https://0.0.0.0/path/to/rest/endpoint*. The hostname or IP part will be ignored.

