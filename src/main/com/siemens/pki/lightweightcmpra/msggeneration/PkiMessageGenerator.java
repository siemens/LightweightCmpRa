/*
 *  Copyright (c) 2020 Siemens AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 */
package com.siemens.pki.lightweightcmpra.msggeneration;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.cmp.PollReqContent;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

import com.siemens.pki.lightweightcmpra.cryptoservices.CmsEncryptorBase;
import com.siemens.pki.lightweightcmpra.cryptoservices.DataSigner;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;

/**
 * a generator for PKI messages conforming to Lightweight CMP Profile
 * {@link https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/}
 *
 */
public class PkiMessageGenerator {

    /**
     * needed to generate a cert hash
     */
    private static final BcDigestCalculatorProvider BC_DIGEST_CALCULATOR_PROVIDER =
            new BcDigestCalculatorProvider();

    /**
     * see rfc4210, D.1.4
     *
     * A constant representing the <code>NULL-DN</code> (NULL distinguished
     * name).
     */
    public static final GeneralName NULL_DN =
            new GeneralName(new X500Name(new RDN[0]));

    /**
     * the certReqId is always 0
     */
    public static final ASN1Integer CERT_REQ_ID_0 = new ASN1Integer(0);

    /**
     * randomness is important
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * needed to generate a cert hash
     */
    static private DigestAlgorithmIdentifierFinder DIG_ALG_FINDER =
            new DefaultDigestAlgorithmIdentifierFinder();

    /**
     * build a {@link HeaderProvider} out the header of a message
     *
     * @param msg
     *            message to use for header rebuilding
     * @return a new build {@link HeaderProvider} holding the MessageTime,
     *         Recipient, RecipNonce, Sender, SenderNonce, TransactionID and
     *         GeneralInfo of the msg
     */
    public static HeaderProvider buildForwardingHeaderProvider(
            final PKIMessage msg) {
        return new HeaderProvider() {
            private final PKIHeader header = msg.getHeader();

            @Override
            public InfoTypeAndValue[] getGeneralInfo() {
                return header.getGeneralInfo();
            }

            @Override
            public ASN1GeneralizedTime getMessageTime() {
                return header.getMessageTime();
            }

            @Override
            public GeneralName getRecipient() {
                return header.getRecipient();
            }

            @Override
            public byte[] getRecipNonce() {
                final ASN1OctetString recipNonce = header.getRecipNonce();
                return recipNonce != null ? recipNonce.getOctets() : null;
            }

            @Override
            public GeneralName getSender() {
                return header.getSender();
            }

            @Override
            public byte[] getSenderNonce() {
                final ASN1OctetString senderNonce = header.getSenderNonce();
                return senderNonce != null ? senderNonce.getOctets() : null;
            }

            @Override
            public ASN1OctetString getTransactionID() {
                return header.getTransactionID();
            }
        };
    }

    /**
     * build a {@link HeaderProvider} for a response to a given message message
     *
     * @param msg
     *            message to answer
     * @return a new build {@link HeaderProvider} response holding the
     *         MessageTime,
     *         TransactionID, Recipient from Sender, RecipNonce from SenderNonce
     *         of the msg and a fresh SenderNonce
     */
    public static HeaderProvider buildRespondingHeaderProvider(
            final PKIMessage msg) {
        return new HeaderProvider() {
            private final PKIHeader header = msg.getHeader();

            @Override
            public InfoTypeAndValue[] getGeneralInfo() {
                return null;
            }

            @Override
            public ASN1GeneralizedTime getMessageTime() {
                return new ASN1GeneralizedTime(new Date());
            }

            @Override
            public GeneralName getRecipient() {
                return header.getSender();
            }

            @Override
            public byte[] getRecipNonce() {
                final ASN1OctetString senderNonce = header.getSenderNonce();
                return senderNonce != null ? senderNonce.getOctets() : null;
            }

            @Override
            public GeneralName getSender() {
                return null;
            }

            @Override
            public byte[] getSenderNonce() {
                final byte[] byteString = new byte[16];
                RANDOM.nextBytes(byteString);
                return byteString;
            }

            @Override
            public ASN1OctetString getTransactionID() {
                return header.getTransactionID();
            }
        };
    }

    /**
     * generate and protect a new CMP message
     *
     * @param headerProvider
     *            PKI header
     * @param protectionProvider
     *            PKI protection
     * @param body
     *            message body
     * @return a fully build and protected message
     * @throws Exception
     *             in case of error
     */
    public static PKIMessage generateAndProtectMessage(
            final HeaderProvider headerProvider,
            final ProtectionProvider protectionProvider, final PKIBody body)
            throws Exception {
        return generateAndProtectMessage(headerProvider, protectionProvider,
                body, null);
    }

    /**
     * generate and protect a new CMP message
     *
     * @param headerProvider
     *            PKI header
     * @param protectionProvider
     *            PKI protection
     * @param body
     *            message body
     * @param issuingChain
     *            chain of enrolled certificate to append at the
     *            extraCerts
     * @return a fully build and protected message
     * @throws Exception
     *             in case of error
     */
    public static PKIMessage generateAndProtectMessage(
            final HeaderProvider headerProvider,
            final ProtectionProvider protectionProvider, final PKIBody body,
            final List<CMPCertificate> issuingChain) throws Exception {
        GeneralName sender = protectionProvider.getSender();
        if (sender == null) {
            sender = headerProvider.getSender();
        }
        final GeneralName recipient = headerProvider.getRecipient();
        final PKIHeaderBuilder headerBuilder = new PKIHeaderBuilder(
                PKIHeader.CMP_2000, sender != null ? sender : NULL_DN,
                recipient != null ? recipient : NULL_DN);
        headerBuilder.setMessageTime(headerProvider.getMessageTime());
        headerBuilder.setProtectionAlg(protectionProvider.getProtectionAlg());
        headerBuilder.setSenderKID(protectionProvider.getSenderKID());
        final ASN1OctetString transactionID = headerProvider.getTransactionID();
        headerBuilder.setTransactionID(transactionID);
        headerBuilder.setSenderNonce(headerProvider.getSenderNonce());
        headerBuilder.setRecipNonce(headerProvider.getRecipNonce());
        headerBuilder.setGeneralInfo(headerProvider.getGeneralInfo());
        final PKIHeader generatedHeader = headerBuilder.build();
        final ProtectedPart protectedPart =
                new ProtectedPart(generatedHeader, body);
        final DERBitString protection =
                protectionProvider.getProtectionFor(protectedPart);
        final List<CMPCertificate> protectingExtraCerts =
                protectionProvider.getProtectingExtraCerts();
        final List<CMPCertificate> generatedExtraCerts = new ArrayList<>();
        if (protectingExtraCerts != null) {
            generatedExtraCerts.addAll(protectingExtraCerts);
        }
        if (issuingChain != null && !issuingChain.isEmpty()) {
            for (final CMPCertificate akt : issuingChain) {
                if (!generatedExtraCerts.contains(akt)) {
                    generatedExtraCerts.add(akt);
                }
            }
        }
        return new PKIMessage(generatedHeader, body, protection,
                generatedExtraCerts.isEmpty() ? null
                        : generatedExtraCerts
                                .toArray(new CMPCertificate[generatedExtraCerts
                                        .size()]));
    }

    /**
     * generate a CertConf body
     *
     * @param certificate
     *            certificate to confirm
     * @return a CertConf body
     * @throws Exception
     *             in case of error
     */
    public static PKIBody generateCertConfBody(final CMPCertificate certificate)
            throws Exception {
        final AlgorithmIdentifier digAlg = DIG_ALG_FINDER
                .find(certificate.getX509v3PKCert().getSignatureAlgorithm());
        if (digAlg == null) {
            throw new CMPException(
                    "cannot find algorithm for digest from signature");
        }

        final DigestCalculator digester =
                BC_DIGEST_CALCULATOR_PROVIDER.get(digAlg);
        digester.getOutputStream().write(certificate.getEncoded());
        final ASN1Sequence content = new DERSequence(new CertStatus[] {
                new CertStatus(digester.getDigest(), BigInteger.ZERO,
                        new PKIStatusInfo(PKIStatus.granted))});
        return new PKIBody(PKIBody.TYPE_CERT_CONFIRM,
                CertConfirmContent.getInstance(content));
    }

    /**
     * generate Error body
     *
     * @param failInfo
     *            failinfo from {@link PKIFailureInfo}
     * @param errorDetails
     *            a string describing the problem
     * @return an error body
     */
    public static PKIBody generateErrorBody(final int failInfo,
            final String errorDetails) {
        final PKIFreeText statusString =
                errorDetails != null ? new PKIFreeText(errorDetails) : null;
        final PKIStatusInfo pkiStatusInfo =
                new PKIStatusInfo(PKIStatus.rejection, statusString,
                        new PKIFailureInfo(failInfo));
        return new PKIBody(PKIBody.TYPE_ERROR,
                new ErrorMsgContent(pkiStatusInfo, null, statusString));
    }

    /**
     * generate a IP, CP or KUP body for returning a certificate
     *
     * @param bodyType
     *            PKIBody.TYPE_INIT_REP, PKIBody.TYPE_CERT_REP or
     *            PKIBody.TYPE_KEY_UPDATE_REP
     * @param certificate
     *            the certificate to return
     * @return a IP, CP or KUP body
     */
    public static PKIBody generateIpCpKupBody(final int bodyType,
            final CMPCertificate certificate) {
        final CertResponse[] response = new CertResponse[] {new CertResponse(
                CERT_REQ_ID_0, new PKIStatusInfo(PKIStatus.granted),
                new CertifiedKeyPair(new CertOrEncCert(certificate)), null)};
        return new PKIBody(bodyType, new CertRepMessage(null, response));
    }

    /**
     * generate a IP, CP or KUP body for returning a certificate and the related
     * private key
     *
     * @param bodyType
     *            PKIBody.TYPE_INIT_REP, PKIBody.TYPE_CERT_REP or
     *            PKIBody.TYPE_KEY_UPDATE_REP
     * @param certificate
     *            the certificate to return
     * @param privateKey
     *            the private key to return
     * @param keyEncryptor
     *            CMS encryptor used for private key transport
     * @param keySigner
     *            CMS signer used for private key transport
     * @return a IP, CP or KUP body
     * @throws Exception
     * @throws CMSException
     */
    public static PKIBody generateIpCpKupBody(final int bodyType,
            final CMPCertificate certificate, final PrivateKey privateKey,
            final CmsEncryptorBase keyEncryptor, final DataSigner keySigner)
            throws Exception {
        final EncryptedKey encryptedPrivateKey = new EncryptedKey(
                keyEncryptor.encrypt(keySigner.signPrivateKey(privateKey)));
        final CertResponse[] response =
                new CertResponse[] {new CertResponse(CERT_REQ_ID_0,
                        new PKIStatusInfo(PKIStatus.granted),
                        new CertifiedKeyPair(new CertOrEncCert(certificate),
                                encryptedPrivateKey, null),
                        null)};
        return new PKIBody(bodyType, new CertRepMessage(null, response));
    }

    /**
     * generate a IP, CP or KUP body indication a waiting status
     *
     * @param bodyType
     *            PKIBody.TYPE_INIT_REP, PKIBody.TYPE_CERT_REP or
     *            PKIBody.TYPE_KEY_UPDATE_REP
     * @return a IP, CP or KUP body
     */
    public static PKIBody generateIpCpKupBodyWithWaiting(final int bodyType) {
        final CertResponse[] response =
                new CertResponse[] {new CertResponse(CERT_REQ_ID_0,
                        new PKIStatusInfo(PKIStatus.waiting), null, null)};
        return new PKIBody(bodyType, new CertRepMessage(null, response));
    }

    /**
     * generate a IP, CP or KUP body containing an error
     *
     * @param bodyType
     *            PKIBody.TYPE_INIT_REP, PKIBody.TYPE_CERT_REP or
     *            PKIBody.TYPE_KEY_UPDATE_REP
     * @param failInfo
     *            failinfo from {@link PKIFailureInfo}
     * @param errorDetails
     *            a string describing the problem
     * @return a IP, CP or KUP body
     */
    public static PKIBody generateIpCpKupErrorBody(final int bodyType,
            final int failInfo, final String errorDetails) {
        final PKIStatusInfo pkiStatusInfo = new PKIStatusInfo(
                PKIStatus.rejection, new PKIFreeText(errorDetails),
                new PKIFailureInfo(failInfo));
        final CertResponse[] response = new CertResponse[] {
                new CertResponse(CERT_REQ_ID_0, pkiStatusInfo)};
        return new PKIBody(bodyType, new CertRepMessage(null, response));
    }

    /**
     * generate a IR, CR or KUR body
     *
     * @param bodyType
     *            PKIBody.TYPE_INIT_REQ, PKIBody.TYPE_CERT_REQ or
     *            PKIBody.TYPE_KEY_UPDATE_REQ
     * @param certTemplate
     *            template describing the request
     * @param controls
     *            additional controls for KUR
     *
     * @param privateKey
     *            private key to build the POPO, if set to null, POPO is set to
     *            raVerified
     * @return a IR, CR or KUR body
     * @throws Exception
     *             in case of error
     */
    public static PKIBody generateIrCrKurBody(final int bodyType,
            final CertTemplate certTemplate, final Controls controls,
            final PrivateKey privateKey) throws Exception {
        final CertRequest certReq =
                new CertRequest(CERT_REQ_ID_0, certTemplate, controls);
        if (privateKey == null) {
            return new PKIBody(bodyType, new CertReqMessages(
                    new CertReqMsg(certReq, new ProofOfPossession(), null)));
        }
        final Signature sig;
        final AlgorithmIdentifier sigAlg;
        if (privateKey.getAlgorithm().equalsIgnoreCase("RSA")) {
            sig = Signature.getInstance("SHA256withRSA");
            sigAlg = new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.sha256WithRSAEncryption);
        } else {
            sig = Signature.getInstance("SHA256withECDSA");
            sigAlg = new AlgorithmIdentifier(
                    X9ObjectIdentifiers.ecdsa_with_SHA256);
        }
        sig.initSign(privateKey);
        sig.update(certReq.getEncoded(ASN1Encoding.DER));
        final ProofOfPossession popo = new ProofOfPossession(
                new POPOSigningKey(null, sigAlg, new DERBitString(sig.sign())));
        return new PKIBody(bodyType,
                new CertReqMessages(new CertReqMsg(certReq, popo, null)));
    }

    /**
     * generate a PkiConf body
     *
     * @return a PkiConf body
     */
    public static PKIBody generatePkiConfirmBody() {
        return new PKIBody(PKIBody.TYPE_CONFIRM, new PKIConfirmContent());
    }

    /**
     * generate a PollRep body
     *
     * @param checkAfterTime
     *            time in seconds to elapse before a new pollReq may be
     *            sent by the EE
     * @return a PolRepBody
     */
    public static PKIBody generatePollRep(final int checkAfterTime) {
        return new PKIBody(PKIBody.TYPE_POLL_REP, new PollRepContent(
                CERT_REQ_ID_0, new ASN1Integer(checkAfterTime)));
    }

    public static PKIBody generatePollReq() {
        return new PKIBody(PKIBody.TYPE_POLL_REQ,
                new PollReqContent(CERT_REQ_ID_0));
    }

    /**
     * generate a RR body
     *
     * @param certificate
     *            certificate to revoke
     * @return generated RR body
     */
    public static PKIBody generateRrBody(final CMPCertificate certificate)
            throws Exception {

        final Certificate x509v3pkCert = certificate.getX509v3PKCert();
        return generateRrBody(x509v3pkCert.getIssuer(),
                x509v3pkCert.getSerialNumber());
    }

    /**
     * generate a RR body
     *
     * @param issuer
     *            issuer of certificate to revoke
     * @param serialNumber
     *            serialNumber of certificate to revoke
     * @return generated RR body
     * @throws Exception
     */
    public static PKIBody generateRrBody(final X500Name issuer,
            final ASN1Integer serialNumber) throws IOException {
        final CertTemplateBuilder ctb = new CertTemplateBuilder()
                .setIssuer(issuer).setSerialNumber(serialNumber);
        final ExtensionsGenerator extgen = new ExtensionsGenerator();
        extgen.addExtension(Extension.reasonCode, false, new ASN1Enumerated(0));
        final RevDetails revDetails =
                new RevDetails(ctb.build(), extgen.generate());
        return new PKIBody(PKIBody.TYPE_REVOCATION_REQ,
                new RevReqContent(revDetails));
    }

}
