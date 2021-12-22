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
package com.siemens.pki.lightweightcmpra.msgprocessing;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.config.xmlparser.RAINSTANCE.Downstream;
import com.siemens.pki.lightweightcmpra.config.xmlparser.RAINSTANCE.EnrollmentCredentials;
import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.cryptoservices.CmsEncryptorBase;
import com.siemens.pki.lightweightcmpra.cryptoservices.DataSigner;
import com.siemens.pki.lightweightcmpra.cryptoservices.KeyPairGeneratorFactory;
import com.siemens.pki.lightweightcmpra.cryptoservices.TrustCredentialAdapter;
import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;
import com.siemens.pki.lightweightcmpra.msgvalidation.BaseCmpException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpEnrollmentException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpValidationException;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

/**
 * representation of a downstream interface of a RA
 *
 */
class RaDownstream extends BasicDownstream {
    /**
     * a result tuple
     */
    private class HandleCertificateRequestResult {
        PKIMessage handledMessage;
        PrivateKey newGeneratedPrivateKey;

        public HandleCertificateRequestResult(final PKIMessage handledMessage) {
            this.handledMessage = handledMessage;
            this.newGeneratedPrivateKey = null;
        }

        public HandleCertificateRequestResult(final PKIMessage handledMessage,
                final PrivateKey newGeneratedPrivateKey) {
            this.handledMessage = handledMessage;
            this.newGeneratedPrivateKey = newGeneratedPrivateKey;
        }
    }

    private static final Logger LOGGER =
            LoggerFactory.getLogger(RaDownstream.class);

    protected final Function<PKIMessage, PKIMessage> upstreamHandler;

    protected final TransactionStateTracker transactionStateHandler =
            new TransactionStateTracker(INTERFACE_NAME);

    private final TrustCredentialAdapter enrollmentValidator;

    private final InventoryIF inventory;

    private final boolean enforceRaVerified;

    private DataSigner keySigner;

    /**
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @param upstreamHandler
     *            related upstream interface handler
     * @param enrollmentCredentialscredentials
     *            to be used for enrolled certificate validation
     * @throws Exception
     *             in case of error
     */
    RaDownstream(final Downstream config,
            final Function<PKIMessage, PKIMessage> upstreamHandler,
            final EnrollmentCredentials enrollmentCredentials,
            final boolean enforceRaVerified) throws Exception {
        super(config, config.isAcceptRaVerified(), PKIBody.TYPE_INIT_REQ,
                PKIBody.TYPE_CERT_REQ, PKIBody.TYPE_KEY_UPDATE_REQ,
                PKIBody.TYPE_P10_CERT_REQ, PKIBody.TYPE_POLL_REQ,
                PKIBody.TYPE_CERT_CONFIRM, PKIBody.TYPE_REVOCATION_REQ,
                PKIBody.TYPE_GEN_MSG);
        enrollmentValidator = new TrustCredentialAdapter(enrollmentCredentials);
        this.upstreamHandler = upstreamHandler;
        this.enforceRaVerified = enforceRaVerified;
        // TODO init inventory stuff here
        inventory = InventoryIF.DummyInventory;
        keySigner = outputProtector.getKeySigner();
        if (keySigner == null && config.getCentralKeyGeneration() != null) {
            keySigner = new DataSigner(
                    config.getCentralKeyGeneration().getKeyStorePath(),
                    config.getCentralKeyGeneration().getKeyStorePassword());
        }
    }

    /**
     * special handling for CR, IR, KUR
     *
     * @param incomingCertificateRequest
     * @return handled message and maybe a new private key in case of central
     *         key generation
     * @throws Exception
     *             in case of error
     */
    private HandleCertificateRequestResult handleCertificateRequest(
            final PKIMessage incomingCertificateRequest) throws Exception {
        {
            //  check request against inventory
            final PKIMessage request =
                    inventory.checkAndModifyRequest(incomingCertificateRequest);
            final PKIBody pkiBody = request.getBody();
            final CertReqMsg certReqMsg =
                    ((CertReqMessages) pkiBody.getContent())
                            .toCertReqMsgArray()[0];
            final CertRequest certRequest = certReqMsg.getCertReq();
            final CertTemplate certTemplate = certRequest.getCertTemplate();
            final SubjectPublicKeyInfo subjectPublicKeyInfo =
                    certTemplate.getPublicKey();
            if (subjectPublicKeyInfo == null || subjectPublicKeyInfo
                    .getPublicKeyData().getBytes().length == 0) {
                // central key generation requested
                if (keySigner == null) {
                    throw new CmpEnrollmentException(incomingCertificateRequest,
                            INTERFACE_NAME, PKIFailureInfo.notAuthorized,
                            "no credentials for key signing available");
                }
                final KeyPairGenerator kpgen;
                if (subjectPublicKeyInfo != null) {
                    // end entity has a preference on the key type to be generated
                    final ASN1ObjectIdentifier algorithm =
                            subjectPublicKeyInfo.getAlgorithm().getAlgorithm();
                    if (X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm)) {
                        kpgen = KeyPairGeneratorFactory.getEcKeyPairGenerator(
                                subjectPublicKeyInfo.getAlgorithm()
                                        .getParameters().toString());
                    } else if (PKCSObjectIdentifiers.rsaEncryption
                            .equals(algorithm)) {
                        final AttributeTypeAndValue[] controls = certRequest
                                .getControls().toAttributeTypeAndValueArray();
                        int rsaKeyLen = 2048;
                        if (controls != null) {
                            for (final AttributeTypeAndValue aktControl : controls) {
                                if (NewCMPObjectIdentifiers.regCtrl_rsaKeyLen
                                        .equals(aktControl.getType())) {
                                    rsaKeyLen = ASN1Integer
                                            .getInstance(aktControl.getValue())
                                            .getPositiveValue().intValue();
                                    break;
                                }
                            }
                        }
                        kpgen = KeyPairGeneratorFactory
                                .getRsaKeyPairGenerator(rsaKeyLen);
                    } else {
                        // maybe the JCE can help
                        kpgen = KeyPairGenerator.getInstance(algorithm.getId());
                    }
                } else {
                    // end entity has no preference on the key type to be generated
                    kpgen = KeyPairGeneratorFactory
                            .getRsaKeyPairGenerator(2048);
                }
                final KeyPair keyPair = kpgen.genKeyPair();
                // regenerate template but with newly generated public key
                final CertTemplate certTemplateWithPublicKey =
                        new CertTemplateBuilder()
                                .setSubject(certTemplate.getSubject())
                                .setExtensions(certTemplate.getExtensions())
                                .setPublicKey(SubjectPublicKeyInfo.getInstance(
                                        keyPair.getPublic().getEncoded()))
                                .build();
                final PrivateKey privateKey = keyPair.getPrivate();
                return new HandleCertificateRequestResult(
                        new PKIMessage(request.getHeader(),
                                PkiMessageGenerator.generateIrCrKurBody(
                                        pkiBody.getType(),
                                        certTemplateWithPublicKey,
                                        certRequest.getControls(),
                                        enforceRaVerified ? null : privateKey)),
                        privateKey);

            }
            final ProofOfPossession popo = certReqMsg.getPopo();
            if (popo == null) {
                // popo invalid, regenerate body
                return new HandleCertificateRequestResult(
                        new PKIMessage(request.getHeader(),
                                PkiMessageGenerator.generateIrCrKurBody(
                                        pkiBody.getType(), certTemplate,
                                        certRequest.getControls(), null)));
            }

            if (popo.getType() == ProofOfPossession.TYPE_RA_VERIFIED
                    && incomingCertificateRequest.equals(request)) {
                // nothing has changed, nothing needs to be changed
                return new HandleCertificateRequestResult(request);
            }
            if (!enforceRaVerified
                    && popo.getType() == ProofOfPossession.TYPE_SIGNING_KEY) {

                // initial POPO still there and maybe usable again
                final POPOSigningKey popoSigningKey =
                        (POPOSigningKey) popo.getObject();
                final ASN1ObjectIdentifier algorithm =
                        subjectPublicKeyInfo.getAlgorithm().getAlgorithm();
                final PublicKey publicKey = KeyFactory
                        .getInstance(algorithm.toString(),
                                CertUtility.BOUNCY_CASTLE_PROVIDER)
                        .generatePublic(
                                new X509EncodedKeySpec(subjectPublicKeyInfo
                                        .getEncoded(ASN1Encoding.DER)));
                final Signature sig =
                        Signature.getInstance(
                                popoSigningKey.getAlgorithmIdentifier()
                                        .getAlgorithm().getId(),
                                CertUtility.BOUNCY_CASTLE_PROVIDER);
                sig.initVerify(publicKey);
                sig.update(certRequest.getEncoded(ASN1Encoding.DER));
                if (sig.verify(popoSigningKey.getSignature().getBytes())) {
                    // POPO still valid, continue to use it
                    return new HandleCertificateRequestResult(request);
                }
            }
            // popo unusable, set raVerified
            return new HandleCertificateRequestResult(new PKIMessage(
                    request.getHeader(),
                    new PKIBody(pkiBody.getType(),
                            new CertReqMessages(new CertReqMsg(certRequest,
                                    new ProofOfPossession(),
                                    certReqMsg.getRegInfo())))));
        }
    }

    @Override
    protected PKIMessage handleValidatedInputMessage(
            final PKIMessage incomingRequest) {
        try {
            final PKIMessage request;
            final PrivateKey newPrivateKey;
            switch (incomingRequest.getBody().getType()) {
            case PKIBody.TYPE_INIT_REQ:
            case PKIBody.TYPE_CERT_REQ:
            case PKIBody.TYPE_KEY_UPDATE_REQ:
                final HandleCertificateRequestResult handleResult =
                        handleCertificateRequest(incomingRequest);
                request = handleResult.handledMessage;
                newPrivateKey = handleResult.newGeneratedPrivateKey;
                break;
            default:
                request = incomingRequest;
                newPrivateKey = null;
            }
            transactionStateHandler.trackMessage(request);
            final PKIMessage responseFromUpstream =
                    upstreamHandler.apply(request);
            transactionStateHandler.trackMessage(responseFromUpstream);
            if (responseFromUpstream.getBody()
                    .getType() == PKIBody.TYPE_ERROR) {
                return responseFromUpstream;
            }
            final List<X509Certificate> extraCertsAsX509;
            CMPCertificate[] extraCerts = responseFromUpstream.getExtraCerts();
            if (extraCerts != null) {
                // drop self-signed extra certs, but always keep 1st extra cert, even if is self
                // signed
                final List<CMPCertificate> trimmedExtraCerts =
                        new ArrayList<>(extraCerts.length);
                extraCertsAsX509 = new ArrayList<>(extraCerts.length);
                boolean firstCertificateCopied = false;
                for (final CMPCertificate aktCert : extraCerts) {
                    final X509Certificate aktCertAsX509 =
                            CertUtility.certificateFromCmpCertificate(aktCert);
                    if (!firstCertificateCopied
                            || !CertUtility.isSelfSigned(aktCertAsX509)) {
                        trimmedExtraCerts.add(aktCert);
                        extraCertsAsX509.add(aktCertAsX509);
                        firstCertificateCopied = true;
                    }
                }
                if (trimmedExtraCerts.size() < extraCerts.length) {
                    extraCerts = trimmedExtraCerts.toArray(
                            new CMPCertificate[trimmedExtraCerts.size()]);
                }
            } else {
                extraCertsAsX509 = new ArrayList<>();
            }
            final PKIBody bodyFromUpstream = responseFromUpstream.getBody();
            List<CMPCertificate> issuingChain = null;
            final int responseType = bodyFromUpstream.getType();
            switch (responseType) {
            case PKIBody.TYPE_INIT_REP:
            case PKIBody.TYPE_CERT_REP:
            case PKIBody.TYPE_KEY_UPDATE_REP:
                try {
                    final int requestType = request.getBody().getType();
                    if (responseType - requestType != 1
                            && requestType != PKIBody.TYPE_POLL_REQ
                            && requestType != PKIBody.TYPE_P10_CERT_REQ) {
                        throw new CmpValidationException(INTERFACE_NAME,
                                PKIFailureInfo.badMessageCheck,
                                "unexpected certificate response to request: "
                                        + MessageDumper
                                                .msgAsShortString(request)
                                        + "->" + MessageDumper.msgAsShortString(
                                                responseFromUpstream));
                    }
                    try {
                        final CertRepMessage certRep =
                                (CertRepMessage) bodyFromUpstream.getContent();
                        final CMPCertificate enrolledCertificate =
                                certRep.getResponse()[0].getCertifiedKeyPair()
                                        .getCertOrEncCert().getCertificate();
                        final X509Certificate enrolledCertificateAsX509 =
                                CertUtility.certificateFromCmpCertificate(
                                        enrolledCertificate);
                        // there is really a certificate and not only an error in the response
                        final List<? extends X509Certificate> issuingChainAsX509 =
                                enrollmentValidator.validateCertAgainstTrust(
                                        enrolledCertificateAsX509,
                                        extraCertsAsX509);
                        inventory.storeCerificate(enrolledCertificateAsX509,
                                responseFromUpstream);
                        issuingChain =
                                new ArrayList<>(issuingChainAsX509.size());
                        for (final X509Certificate aktCert : issuingChainAsX509) {
                            if (!aktCert.equals(enrolledCertificateAsX509)) {
                                issuingChain.add(CMPCertificate
                                        .getInstance(aktCert.getEncoded()));
                            }
                        }
                        if (newPrivateKey != null) {
                            // central key generation, return the private key too
                            // apply new protection
                            final CMPCertificate[] incomingFirstExtraCerts =
                                    incomingRequest.getExtraCerts();
                            final CmsEncryptorBase keyEncryptor =
                                    outputProtector.getKeyEncryptor(
                                            incomingFirstExtraCerts != null
                                                    && incomingFirstExtraCerts.length > 0
                                                            ? incomingFirstExtraCerts[0]
                                                            : null);
                            final PKIBody newResponseBody = PkiMessageGenerator
                                    .generateIpCpKupBody(responseType,
                                            enrolledCertificate, newPrivateKey,
                                            keyEncryptor, keySigner);
                            return outputProtector.generateAndProtectMessage(
                                    PkiMessageGenerator
                                            .buildForwardingHeaderProvider(
                                                    responseFromUpstream),
                                    newResponseBody, issuingChain);
                        }
                    } catch (final NullPointerException ex) {
                        // could not extract an enrolled certificate from response
                    }
                } catch (final BaseCmpException ex) {
                    throw ex;
                } catch (final Exception ex) {
                    // response broken, without certificate or could not build enrollment chain
                    throw new CmpProcessingException(INTERFACE_NAME,
                            PKIFailureInfo.wrongAuthority,
                            "could not validate enrolled certificate: "
                                    + ex.getLocalizedMessage());
                }
                break;
            default:
                // other message type without enrollment chain
            }
            return outputProtector.protectAndForwardMessage(
                    new PKIMessage(responseFromUpstream.getHeader(),
                            bodyFromUpstream,
                            responseFromUpstream.getProtection(), extraCerts),
                    issuingChain);
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Exception ex) {
            LOGGER.error("exception at downstream interface", ex);
            throw new CmpProcessingException(INTERFACE_NAME,
                    PKIFailureInfo.systemFailure, ex);
        }
    }
}
