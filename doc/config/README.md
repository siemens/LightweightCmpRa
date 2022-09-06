# Configuration of the Lightweight CMP RA

The **Lightweight CMP RA** behavior is specified in configuration files.
On startup,
the path name of each configuration file is given as a command line parameter.

A configuration file must be written in [YAML](https://yaml.org/spec/).
Embedding [JSON](http://json-schema.org/) in YAML is also supported.
A configuration file is structured in hierarchical sections holding

* key/value pairs. This scalar value is a numeric, string, boolean or binary constant.
* key/array pairs. The value, also called list, tuple, vector, sequence holds multiple values.
* Key/object pairs. The subordinate objects may have scalar, array or object values.

So the general structure could looks like this:

```yaml
toplevelobject:
  key1: "value 1"
  key2: Value2
    subobject1:
      key3: "value 3"
      key4: Value4
    arrayKey:
      - "value 7"
      - value8

  ... more nested entities

    subobject2:
      key5: value5
      key6: "Value 6"
```

or

```json
"toplevelobject": {
    "key1" : "value 1",
    "key2" : "Value2",
	"subobject1" : {
	   "key3" : "value 3",
	   "key4" : "Value4",

	  "___COMMENT___":  "more nested entities"

	},
	"arrayKey:" ["value 7", "value8"],
	"subobject2" : {
	     "key5" : "value5",
	     "key6" : "Value 6"
	}
}
```


Each configuration file must contain a configuration for exactly one RA.
In productive use, configuration files should be integrity protected
because they contain critial data such as trust anchors.

Example configuration files can be found in the
[Test Configuration](/src/test/java/com/siemens/pki/lightweightcmpra/test/config).

**Keys and string-like values of configuration objects are case insensitive, while
Uniform Resource Identifiers (URI), directory names, shared secrets, and passwords
are case sensitive.**

The format and syntax of an URI is specified in
[RFC2396](https://www.ietf.org/rfc/rfc2396.txt).


## Top-level Structure

The **Top-level Structure** determines the overall behavior of an RA instance.
It may contain declarations of the object types listed below in any order:

| mandatory/optional| object type |
|-------------------------|:------------|
| mandatory| [`DownstreamInterface` object](#the-downstreaminterface-object) |
| mandatory if messages need to be sent upstream | [`UpstreamInterface` object](#the-upstreaminterface-object) |
| mandatory| [`DownstreamConfiguration` object](#the-downstreamconfiguration-object) |
| mandatory if incoming IR, CR or KUR shall be processed | [`RaVerifiedAcceptable` object](#the-raverifiedacceptable-object)|
| mandatory if delayed delivery shall be supported | [`RetryAfterTimeInSeconds` object](#the-retryaftertimeinseconds-object) |
| mandatory if messages need to be sent upstream | [`UpstreamConfiguration` object](#the-upstreamconfiguration-object) |
| mandatory if IR, CR or KUR needs to be sent upstream | [`ForceRaVerifyOnUpstream` object](#the-forceraverifyonupstream-object) |
| mandatory if IP, CP or KUP shall be processed | [`EnrollmentTrust` object](#the-enrollmenttrust-object) |
| mandatory if central key generation shall be supported | [`CkgConfiguration` object](#the-ckgconfiguration-object) |
| mandatory if GENM shall be processed locally | [`SupportMessageHandlerInterface` object](#the-supportmessagehandlerinterface-object)|
| mandatory if interaction with an inventory is required | [`InventoryInterface` object](#the-inventoryinterface-object) |

All objects except `DownstreamInterface` have array values.
If an object type is not mandatory, an empty array may given or the whole key may be absent.

For `UpstreamInterface`, `DownstreamConfiguration`, `RaVerifiedAcceptable`, `RetryAfterTimeInSeconds`,
`UpstreamConfiguration`, `ForceRaVerifyOnUpstream`, `EnrollmentTrust`, `CkgConfiguration`, and `InventoryInterface`
each array entry may have a **certProfile** value included. The value of a **certProfile** is a string.
An absent **certProfile** matches CMP messages with any (or no) certProfile.

For `DownstreamConfiguration`, `RaVerifiedAcceptable`, `RetryAfterTimeInSeconds`,
`UpstreamConfiguration`, `ForceRaVerifyOnUpstream`,
`EnrollmentTrust`, `CkgConfiguration`, and `InventoryInterface`
each array entry may have a **bodyType** included.

The value of the **bodyType** is a number (0..26) or a string (`"ir"`..`"pollRep"`).
An absent **bodyType** matches CMP messages of any type.

While processing a CMP message (which may be a request or response, including
an error message), its bodyType (see
[RFC4210](https://datatracker.ietf.org/doc/html/rfc4210),
section PKI Message Body) and any certProfile optionally given in the message header (see
[CMP updates](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cmp-updates),
section certProfile)
are extracted from the message and matched against the array entries
until a fully matching entry was found. This first matching entry is then used
and controls the further processing of the message.

For the `SupportMessageHandlerInterface` object value each array entry
the implicit bodyType is `"genm"` and it may have a **certProfile**
and/or an **InfoTypeOid** included.
The **certProfile** handling is the same as described above.
The value of a **InfoTypeOid** is a OID string (e.g., `"1.3.5.6.7.99"`).
This **InfoTypeOid** is matched against the OID in the first InfoType of a GenMsg.
If the InfoTypeOid was not specified, the OIDs defined in
[CMP updates](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cmp-updates),
section Root CA Certificate Update, Certificate Request Template, and
CRL Update Retrieval depending on the specific handler are used for matching.
If under some conditions such array is not mandatory, the whole key might be absent or the array might be empty.


## The `DownstreamInterface` object

The **`DownstreamInterface` object** describes the transport layer
of the downstream interface from which the component receives CMP requests.

It must contain exactly one of the objects described below:

|object type |
|-------------|
| [`HttpServer` object](#the-httpserver-object) |
| [`HttpsServer` object](#the-httpsserver-object) |
| [`CoapServer` object](#the-coapserver-object) |
| [`OfflineFileServer` object](#the-offlinefileserver-object) |

### The `HttpServer` object

The **`HttpServer` object** describes the instantiation
of the downstream interface to an HTTP server.
Its used for CMP request reception and response delivery
as specified in [RFC 6712](https://www.rfc-editor.org/rfc/rfc6712.txt).

It must contain the key/value pair described below:

| mandatory/optional|default | key | value type| value description|
|-|-|-|-|-|
| mandatory|| ServingUri | URI | the HTTP path to be served |

The hostname or IP part of the **ServingUri** will be ignored.

### The `HttpsServer` object

The **`HttpsServer` object** describes the instantiation
of the downstream interface to an HTTPS server.
Its used for CMP request reception and response delivery
as specified in [RFC 6712](https://www.rfc-editor.org/rfc/rfc6712.txt).

It must contain the key/value pairs described below in any order:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
|mandatory||ServingUri|URI|the HTTPS path to be served|
|optional|accept all|serverTrust|[`VerificationContext`](#the-verificationcontext-object)| TLS server trust|
|mandatory||serverCredentials|[`SignatureCredentialContext`](#the-signaturecredentialcontext-object)|TLS server credentials|

The hostname or IP part of the **ServingUri** will be ignored.
The serverTrust and serverCredentials describe the TLS server configuration.

### The `CoapServer` object

The **`CoapServer` object** describes the instantiation
of the downstream interface to a CoAP endpoint as described in
[RFC 7252](https://www.rfc-editor.org/rfc/rfc7252.txt).
The UDP server binds to the standard CoAP port 5683.

It must contain the key/value pair described below:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
| mandatory| |ServerPath | string | the CoAP path to be served |

### The `OfflineFileServer` object

The **`OfflineFileServer` object** describes the instantiation
of the downstream interface to a file system interface.

It should contain the key/value pairs described below in any order:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
| mandatory||inputDirectory| string| the relative or absolute path to a directory that is scanned repeatedly for files containing a DER-encoded CMP request messages. Such messages are processed in the same way as other incoming messages.|
| mandatory| | outputDirectory| string| the relative or absolute path to a directory used to write outgoing-DER encoded CMP messages. |
| optional|10s| inputDirectoryPollcycle|integer| the input directory polling cycle in seconds.|


## The `UpstreamInterface` object

The **`UpstreamInterface` object** describes the transport layers
of the upstream interface to which the component may send/forward CMP requests.
It may be omitted if all CMP messages can be handled locally
(e.g., support messages only that are not forwarded to an upstream server).


The value array contains

| requested cardinality | object type |
|-------------------------|-------------|
|0..n| [`HttpClient` object](#the-httpclient-object) |
|0..n| [`HttpsClient` object](#the-httpclient-object) |
|0..n| [`OfflineFileClient` object](#the-offlinefileclient-object) |


### The `HttpClient` object

The **`HttpClient` object** describes the instantiation of
the upstream interface to an HTTP client.

It must contain the key/value pair described below:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
| mandatory| | ServingUri|URI|server URL to connect to |

### The `HttpsClient` object

The **`HttpsClient` object** describes the instantiation of
the upstream interface to an HTTPS/TLS client.

It should contain the key/value pairs described below in any order:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
| mandatory || ServingUri|URI|server URL to connect to |
|optional|accept all|ClientTrust|[`VerificationContext`](#the-verificationcontext-object)|TLS client trust|
|optional||ClientCredentials|[`SignatureCredentialContext`](#the-signaturecredentialcontext-object)|TLS client credentials|

### The `OfflineFileClient` object

The **`OfflineFileClient` object** describes the instantiation of the upstream interface to a file system interface.

It should contain the key/value pairs described below in any order:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
| mandatory| | outputDirectory|string|the relative or absolute path to a directory used to write outgoing DER-encoded CMP request messages |
| mandatory| | inputDirectory|string|the relative or absolute path to a directory which is scanned repeatedly for files containing a DER-encoded CMP response messages. Such messages are processed in the same way as other incoming messages. |
| optional|10 s|inputDirectoryPollcycle|integer|the number of seconds between input directory polls|


## The `DownstreamConfiguration` object

The **`DownstreamConfiguration` object** describes the behavior of
a downstream CMP interface.

The value array contains

| requested cardinality | object type |
|-------------------------|-------------|
|1..n| [`CmpMessageInterface` values](#the-cmpmessageinterface-value).|


## The `RaVerifiedAcceptable` object

The **`RaVerifiedAcceptable` object** specifies whether for incoming IR, CR, KUR
the `RaVerified` value is acceptable as POPO.

The value array contains

| requested cardinality | key | value type| value description |
|-------------------------|-------------|----|----|
|0..n| value |boolean|true if `RaVerified` for incoming IR, CR, KUR is acceptable.|


## The `RetryAfterTimeInSeconds` object

The **`RetryAfterTimeInSeconds` object** specifies the retryAfter time in seconds
to return in a POLLREP on the downstream interface in case of delayed delivery.

The value array contains

| requested cardinality | key | value type| value description |
|-------------------------|-------------|----|----|
|0..n| value |integer|retryAfter time in seconds|


## The `UpstreamConfiguration` object

The **`UpstreamConfiguration` object** describes the behavior of
an upstream CMP interface.

The value array contains

| requested cardinality | object type |
|-------------------------|-------------|
|0..n| [`CmpMessageInterface` values](#the-cmpmessageinterface-value).|


## The **`ForceRaVerifyOnUpstream` object

The **`ForceRaVerifyOnUpstream` object** controls if
for outgoing upstream IR, CR, KUR the POPO is set to RaVerified.

The value array contains

| requested cardinality | key | value type| value description |
|-------------------------|-------------|-------|------|
|0..n| value |boolean| if set to "true", the POPO is set to RaVerified for outgoing upstream IR, CR and KUR.


### The `CmpMessageInterface` value

The **`CmpMessageInterface` value** describes the behavior of an CMP interface
(upstream or downstream) matching the certProfile and the bodyType.

It may contain the key/value pairs described below in any order:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
|optional|accept all|`VerificationContext`|[`VerificationContext` object](#the-verificationcontext-object)|trust for protection validation of incoming messages|
| optional|mandatory for reprotect | outputCredentials| [`OutputCredentials` object](#the-outputcredentials-object) | determines protection of outgoing messages
| optional|no special processing of nested messages |`NestedEndpointContext`| [`NestedEndpointContext` object](#the-nestedendpointcontext-object) |determines processing of nested messages
| optional|**reprotect** |ReprotectMode|enum { **reprotect, strip, keep** } |protection mode for outgoing message|
| optional|3600 seconds| AllowedMessageTimeDeviation|integer value | the maximum acceptable age in seconds of an incoming message according to its messageTime |
| optional|false | CacheExtraCerts| boolean| whether received extra certificates should be cached |
| optional|false | SuppressRedundantExtraCerts|boolean| whether to prevent repeated inclusion of certificates in the extraCerts field of outgoing messages within a transaction.|

#### The `VerificationContext` object

The **`VerificationContext` object** describes all values needed to authenticate peers or signed messages. If the `VerificationContext` is optional
and not given then no verification or authentication is done.

It contains all of the key/value pairs described below in any order:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
|mandatory for validation based on a shared secret||SharedSecret|array of byte|a shared secret if validation based on a shared secret should be supported. |
|mandatory for signature-based validation||TrustedCertificates|array of URI|location of all trusted certificates. This and the following key/value pairs are relevant only if signature-based validation should be supported.|
|optional|absent|AdditionalCerts|array of URI|location of additional intermediate certificates that can be used for certificate chain building|
|optional|absent|CRLs|array of URI|location of additional Certificate Revocation Lists that can be used for cert status checks|
|optional|false|CDPsEnabled|boolean|whether CRL Distribution Point (CDP) certificate extensions should be used for cert status checks|
|optional|absent|OCSPResponder|URI|location of an OCSP responder that can be used for cert status checks|
|optional|false|AIAsEnabled|boolean|whether Authority Information Access (AIA) certificate extensions should be used for cert status checks|
|optional|empty|PKIXRevocationCheckerOptions|array of enum { **ONLY_END_ENTITY, PREFER_CRLS, NO_FALLBACK, SOFT_FAIL** }|options to control the cert status checks. For details see [Java RevocationChecker](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/cert/PKIXRevocationChecker.html) and [Options](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/cert/PKIXRevocationChecker.Option.html)|

Note:
The current implementation supports only one SharedSecret per `VerificationContext`.
So the only way to specify more than one shared secret per `DownstreamConfiguration`
or `UpstreamConfiguration` is to use more than one **certProfile**.

#### The `OutputCredentials` object

The **`OutputCredentials` object** describes protection for outgoing messages.

It contains exactly one of the key/value pairs described below:

| key | value type| value description|
|-----|-----------|------------------|
|Signature|[`SignatureCredentialContext`](#the-signaturecredentialcontext-object)|if protection shall be signature-based|
|SharedSecret|[`SharedSecretCredentialContext`](#the-sharedsecretcredentialcontext-object)|if protection shall be based on a shared secret|

##### The `SignatureCredentialContext` object

The **`SignatureCredentialContext`** object holds the values needed
for authenticating at TLS level, for signature-based CMP protection,
and for signing other data like centrally generated private keys.

It contains all of the key/value pairs described below in any order:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
|mandatory||KeyStore|URI|location of a keystore holding certificate, private key and certificate chain|
|mandatory||Password|array of byte|password for the KeyStore|
|optional|derived from signing key|SignatureAlgorithmName|string|name or OID of signature algorithm|

##### The `SharedSecretCredentialContext` object

The **`SharedSecretCredentialContext` object** provides all values needed
for CMP protection based on a shared secret.

It must contain the key/value pairs described below in any order,
as far as needed depending on the chosen MAC algorithm.

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
|mandatory||SharedSecret|string|shared secret usable for MAC-based protection|
|optional|"PBMAC1"|PasswordBasedMacAlgorithm|string|"PBMAC1", "PASSWORDBASEDMAC" or OID as string|
|optional|10000|IterationCount|integer|iteration count to use|
|optional|4096|KeyLength|integer|intended key length to be produced|
|optional|"1.2.840.113549.2.9"|MacAlgorithm|string|MAC algorithm name or OID as string|
|optional|HMacSHA256|Prf|string|name of pseudo-random function or one way function to use|
|optional|randomly generated 20 bytes|Salt|array of byte|input salt|
|optional|absent|SenderKID|string|sender key identifier to be used for the CMP message protection, which can be for instance a user name|

#### The `NestedEndpointContext` object

The **`NestedEndpointContext` object** provides values that determine
if and how to unwrap incoming and to wrap outgoing nested messages.
It should contain all needed key/value pairs described below in any order:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
|optional|match all |RecipientPattern|string|if the recipient of an incoming nested message matches this regular expression, the message will be unwrapped|
| optional|accept all | `VerificationContext` |[`VerificationContext` object](#the-verificationcontext-object)|if provided, all elements of incoming nested messages are validated with the given trust.|
| mandatory || outputCredentials| [`OutputCredentials` object](#the-outputcredentials-object) | when a `NestedEndpointContext` object is given, all outgoing messages are nested and protected using these credentials.|

## The `EnrollmentTrust` object

The **`EnrollmentTrust` object** provides a `VerificationContext`
used to validate an enrolled certificate and to calculate the additional
certificates in the extraCerts field of IP, CP and KUP.
Any given SharedSecret key/value is ignored here.

## The `CkgConfiguration` object

The **`CkgConfiguration` object** describes the handling of
central key generation in the RA.

The value array contains all of the objects below in any order:

| requested cardinality | object type |
|---|--|
|0..n| [`CkgKeyAgreementContext` objects](#the-ckgkeyagreementcontext-object) |
|0..n| [`CkgKeyTransportContext` objects](#the-ckgkeytransportcontext-object) |
|0..n| [`CkgPasswordContext` objects](#the-ckgpasswordcontext-object) |


## The `CkgKeyAgreementContext` object

The **`CkgKeyAgreementContext` object** provides all values required
for performing key agreement in context of central key generation.

It contains all of the key/value pairs described below in any order:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
|mandatory||KeyStore|URI|location of a keystore holding certificate, private key and certificate chain for key agreement|
|mandatory||Password|array of byte|password for the KeyStore|
|optional|"1.2.840.113549.1.9.16.3.5", must be consistent with type of key agreement key|KeyAgreementAlg|string|the algorithm (Name or OID) used for key agreement, see <a href="https://tools.ietf.org/wg/lamps/draft-ietf-lamps-cmp-algorithms"> Certificate Management Protocol (CMP) Algorithms</a>, section "Key Agreement Algorithms"
|optional|"2.16.840.1.101.3.4.1.5"|KeyEncryptionAlg|string|the symmetric algorithm (Name or OID) used for key encryption, see <a href="https://tools.ietf.org/wg/lamps/draft-ietf-lamps-cmp-algorithms"> Certificate Management Protocol (CMP) Algorithms </a>, section "Key Management Algorithms"
|optional|"2.16.840.1.101.3.4.1.2"|ContentEncryptionAlg|string|symmetric content encryption algorithm (Name or OID) to build CMS EnvelopedData|
|mandatory||SigningCredentials|[`SignatureCredentialContext`](#the-signaturecredentialcontext-object)|credentials to sign the centrally generated private key. |

### The `CkgKeyTransportContext` object

The **`CkgKeyTransportContext` object** provides all values required
for performing key transport in context of central key generation.

It contains all of the key/value pairs described below in any order:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
|optional|"2.16.840.1.101.3.4.1.2"|ContentEncryptionAlg|string|symmetric content encryption algorithm (Name or OID) to build CMS EnvelopedData|
|mandatory||SigningCredentials|[`SignatureCredentialContext`](#the-signaturecredentialcontext-object)|credentials to sign the centrally generated private key. |

### The `CkgPasswordContext` object

The **`CkgPasswordContext` object** provides all values required
to encrypt the central generated private key.
It contains all of the key/value pairs described below in any order:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
|mandatory||EncryptionCredentials|[`SharedSecretCredentialContext`](#the-sharedsecretcredentialcontext-object)|credentials to encrypt the central generated private key|
|optional|"2.16.840.1.101.3.4.1.2"|KekAlg|string|the KEK algorithm (Name or OID) to use|
|optional|"2.16.840.1.101.3.4.1.2"|ContentEncryptionAlg|string|symmetric content encryption algorithm (Name or OID) to build CMS EnvelopedData|
|mandatory||SigningCredentials|[`SignatureCredentialContext`](#the-signaturecredentialcontext-object)|credentials to sign the centrally generated private key. |

## The `SupportMessageHandlerInterface` object

The **`SupportMessageHandlerInterface` object** controls
the processing of support messages (using genm/gemp).

The value array contains

| requested cardinality | key | value type|
|-------------------------|-------------|----|
|0..n| `GetCaCertificates`| [`GetCaCertificates` objects](#the-getcacertificates-object) |
|0..n| `GetRootCaCertificateUpdate` | [`GetRootCaCertificateUpdate` objects](#the-getrootcacertificateupdate-object)|
|0..n| `GetCertificateRequestTemplate`| [`GetCertificateRequestTemplate` objects](#the-getcertificaterequesttemplate-object) |
|0..n| `CrlUpdateRetrieval`| [`CrlUpdateRetrieval` objects](#the-crlupdateretrieval-object) |

### The `GetCaCertificates` object

The **`GetCaCertificates` object** controls
the handling of a Get CA certificates genm request.

It contains

| requested cardinality | key | value type| value description |
|-------------------------|-------------|----|--|
|0..n|CaCertificates|array of URI|locations of the certificates to return|

### The `GetRootCaCertificateUpdate` object

The **`GetRootCaCertificateUpdate` object** controls
the handling of a Get root CA certificate update genm requests.

It contains all of the key/value pairs described below in any order:

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
| mandatory || newWithNew|URI| location of new root certificate to return|
| mandatory|| newWithOld|URI| location of forward transition certificate to return|
| optional|absent | oldWithNew|URI| location of backward transition certificate to return|

### The `CrlUpdateRetrieval` object

The **`CrlUpdateRetrieval` object** controls
the handling of a CRL Update Retrieval genm request.

It contains

| requested cardinality | key | value type| value description |
|-------------------------|-------------|----|--|
|0..n|crls|array of URI|locations of the CRLs to return|

### The `GetCertificateRequestTemplate` object

The **`GetCertificateRequestTemplate` object** controls
the handling of a Get certificate request template genm requests.

It contains

| mandatory/optional|default | key | value type| value description|
|--|--|--|--|:--|
|mandatory||Template|URI|location of the template, which must be ASN.1 DER-encoded|


## The `InventoryInterface` object

The **`InventoryInterface` object** describes the interface to an external inventory
for checking/modifying certificate requests and reporting enrollment results.

The value array contains

| requested cardinality | key | value type| value description |
|-------------------------|-------------|--|--|
|0..n| ImplementingClass |string|the qualified name of a Java class.|

The string value holds the qualified name of a Java class implementing the
[com.siemens.pki.cmpracomponent.configuration.InventoryInterface](https://github.com/siemens/cmp-ra-component/blob/main/src/main/java/com/siemens/pki/cmpracomponent/configuration/InventoryInterface.java) interface.
On first match of the `InventoryInterface` value array entry
an instance of the given Java class is created
using the parameterless default constructor.
This instance is then used to execute the appropriate methods
of com.siemens.pki.cmpracomponent.configuration.InventoryInterface
when an IR, CR, KUR, IP, CP or KUP message is processed.
