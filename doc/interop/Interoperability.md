# Interoperability with other CMP implementations

The Lightweight CMP RA was tested for interoperability with the implementations mentioned below:

- [OpenSSL 3.0](https://www.openssl.org/source/)
    - OpenSSL 3.0 is the next major version of OpenSSL. It contains a mature CMP library implementation in *C*.

- [CMPforOpenSSL](https://github.com/mpeylo/cmpossl/wiki)
    - The CMPforOpenSSL open-source software project provides a CMP library in C and a CLI based on
    OpenSSL, implementing most of RFC 4210, RFC 4211, and RFC 6712. This software component was
    developed initially by Nokia to support the CMP functionality needed for LTE backbone components
    and is in productive use for many years already.

- [embeddedCMP](https://github.com/siemens/embeddedCMP)
    - The embeddedCMP project has has been developed and published as a proof-of-concept implementation
    for demonstration and standardization purposes to show that CMP can be implemented and used even
    on a device that does not have the capacity to include OpenSSL nor a proper operating system.

- [EJBCA](https://www.ejbca.org/)
    - The EJBCA is a Open Source Certificate Authority.

# Covered PKI management operations

The PKI management operations below have been tested with other implementations:

- Requesting a certificate from a new PKI with signature-based protection
- Updating an existing certificate with signature-based protection
- Responding to a certificate request
- Responding to a confirmation message
- Forwarding messages - not changing protection
- Adding protection to a request message
- Requesting a certificate from a PKI with MAC-based protection
- Revoking a certificate
- Responding to a revocation request
- Acting on behalf of other PKI entities - revoking a certificate
- Requesting an additional certificate with signature-based protection
- Handling delayed enrollment
- Forwarding messages - replacing protection, not changing any included proof-of-possession
- Forwarding messages - replacing protection, breaking proof-of-possession
- Initiating delayed enrollment
- HTTP transport
- Offline transport

# Example message flows

The folder [messsageflows](./messsageflows) contains some message flows for reference purposes. 
Each subfolder contains all messages related to one transaction. Each file in the
subfolder contains exactly one message. Every message is stored in 3 different formats (DER, PEM, ASN.1).
For message files the naming convention below is used:

    <interfacename>_<messagetype>.<messageformat>
    
    e.g. downstream_CERT_CONFIRM.pem
    
- The **<interfacename>** describes the RA interface used to send or receive the message. 
The interface towards the End Entity is usually named as *downstream*. The HTTP(S) client 
interface towards the CA is named as *HTTP_client*.
- The **<messagetype>** describes the abbreviated type of the PKI Message Body. 
It could be for example *INIT_REQ*, *REVOCATION_REP* or *CERT_CONFIRM*.
- The **<messageformat>** file extension describes the data format used to store the message:

    - The *PKI* file extension is used, if the file holds a binary DER encoded message.
    - The *pem* file extension is used, if the file holds a PEM encoded message.
    - The *txt* file extension is used, if the file holds a readable ASN.1 dump of the message.
   
## The IrWithMacProtection message flow

The folder [IrWithMacProtection](/doc/interop/messageflows/IrWithMacProtection) contains a message flow implementing:

- Requesting a certificate from a PKI with MAC-based protection
- Forwarding messages - replacing protection, not changing any included proof-of-possession
- Responding to a certificate request
- Responding to a confirmation message

## The CrWithSignatureProtection message flow

The folder [CrWithSignatureProtection](/doc/interop/messageflows/CrWithSignatureProtection) contains a message flow implementing:

- Requesting an additional certificate with signature-based protection
- Forwarding messages - replacing protection, not changing any included proof-of-possession
- Requesting a certificate from a new PKI with signature-based protection
- Responding to a certificate request
- Responding to a confirmation message

## The Kur message flow

The folder [Kur](/doc/interop/messageflows/Kur) contains a message flow implementing:

- Updating an existing certificate with signature-based protection
- Responding to a certificate request
- Responding to a confirmation message
- Forwarding messages - not changing protection

## The CrDelayed message flow

The folder [CrDelayed](/doc/interop/messageflows/CrDelayed) contains a message flow implementing:

- Requesting a certificate from a new PKI with signature-based protection
- Initiating delayed enrollment
- Handling delayed enrollment
- Responding to a certificate request
- Responding to a confirmation message
- Forwarding messages - replacing protection, not changing any included proof-of-possession

## The Rr message flow

The folder [Rr](/doc/interop/messageflows/Rr) contains a message flow implementing:

- Revoking a certificate
- Responding to a revocation request









