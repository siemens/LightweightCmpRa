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
package com.siemens.pki.lightweightcmpra.msgvalidation;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Date;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.cmp.PollReqContent;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;

import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

/**
 * A CMP message validator to ensure CMP messages conform to RFC 4210.
 *
 */
public class MessageValidator implements ValidatorIF {
    /**
     *
     */
    private static final ASN1Integer ASN1INTEGER_0 = new ASN1Integer(0);

    private final String interfaceName;

    private final boolean acceptRaVerified;

    private final int allowedTimeDeviationInSeconds;

    private final JcaX509ContentVerifierProviderBuilder jcaX509ContentVerifierProviderBuilder =
            new JcaX509ContentVerifierProviderBuilder();

    /**
     *
     * @param interfaceName
     *            later used in validation error messages
     * @param acceptRaVerified
     *            should raVerified be accepted as POPO?
     * @param allowedTimeDeviationInSeconds
     *            tolerated message time deviation
     */
    public MessageValidator(final String interfaceName,
            final boolean acceptRaVerified,
            final int allowedTimeDeviationInSeconds) {
        this.interfaceName = interfaceName;
        this.acceptRaVerified = acceptRaVerified;
        this.allowedTimeDeviationInSeconds = allowedTimeDeviationInSeconds;

    }

    /**
     * Helper method to check whether the class of the given
     * <code>content</code> is
     * equal to the given <code>clazz</code>.
     *
     * @param content
     *            the object to check
     * @param clazz
     *            the expected Class
     * @throws CmpValidationException
     *             if the class of the given <code>content</code> is not equal
     *             to
     *             <code>clazz</code>.
     */
    private void assertContentOfType(final ASN1Encodable content,
            final Class<?> clazz) throws CmpValidationException {
        if (!content.getClass().equals(clazz)) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badMessageCheck,
                    "content is not of type:" + clazz);
        }

    }

    /**
     * Helper method to check whether the given objects <code>value1</code> and
     * <code>value2</code> are equal. If values are not equal, a
     * {@link CmpValidationException} will be thrown.
     *
     * @param value1
     *            the first object which is compared to <code>value2</code>.
     * @param value2
     *            the second object which is compared to <code>value1</code>.
     * @param errorMsg
     *            the error message which should be set to the
     *            {@link CmpValidationException} which will be thrown if both
     *            objects are not equal
     * @throws CmpValidationException
     *             if both object are not equal.
     */
    private void assertEqual(final Object value1, final Object value2,
            final String errorMsg) {
        if (!Objects.equals(value1, value2)) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badDataFormat, errorMsg);
        }

    }

    /**
     * Helper method to check whether the given <code>array</code> is
     * not <code>null</code> and has exactly one element.
     *
     * @param array
     *            the object array to check.
     * @param errorMsg
     *            the error message which should be set to the
     *            {@link CmpValidationException} which will be thrown if the
     *            check fails.
     * @throws CmpValidationException
     *             if the given <code>array</code> is <code>null</code> or
     *             does not contains exactly one element..
     */
    private void assertExactlyOneElement(final Object[] array,
            final int failInfo, final String errorMsg) {
        if (array == null || array.length != 1) {
            throw new CmpValidationException(interfaceName, failInfo, errorMsg);
        }
    }

    /**
     * Helper method to check whether the given <code>value</code> is
     * <code>null</code>.
     *
     * @param value
     *            the value to check whether it is <code>null</code>.
     * @param errorMsg
     *            the error message which should be set to the
     *            {@link CmpValidationException} which will be thrown if
     *            <code>value</code> is not <code>null</code>.
     * @param failInfo
     * @throws CmpValidationException
     *             if the given <code>value</code> is not <code>null</code>
     */
    private void assertIsNull(final Object value, final int failInfo,
            final String errorMsg) {
        if (!Objects.isNull(value)) {
            throw new CmpValidationException(interfaceName, failInfo, errorMsg);
        }

    }

    /**
     * Helper method to check whether the given <code>value</code> is not
     * <code>null</code>.
     *
     * @param value
     *            the value to check if it is not <code>null</code>
     * @param errorMsg
     *            the error message which should be set to the
     *            {@link CmpValidationException} which will be thrown if
     *            <code>value</code> is <code>null</code>.
     * @throws CmpValidationException
     *             if the given <code>value</code> is <code>null</code>
     */
    private void assertNotNull(final Object value, final int failInfo,
            final String errorMsg) {
        if (Objects.isNull(value)) {
            throw new CmpValidationException(interfaceName, failInfo, errorMsg);
        }
    }

    /**
     * Validates the given <code>message</code> to ensure that it conforms to
     * the
     * CMP profile.
     *
     * @param message
     *            the CMP message to validate
     * @throws CmpValidationException
     *             if validation failed
     */
    @Override
    public void validate(final PKIMessage message) {

        validateHeader(message);

        final PKIBody body = message.getBody();
        switch (body.getType()) {
        case PKIBody.TYPE_INIT_REQ:
        case PKIBody.TYPE_CERT_REQ:
        case PKIBody.TYPE_KEY_UPDATE_REQ:
            validateCrmfCertReq(message);
            break;
        case PKIBody.TYPE_P10_CERT_REQ:
            validateP10CertReq(message);
            break;
        case PKIBody.TYPE_CERT_REP:
        case PKIBody.TYPE_INIT_REP:
        case PKIBody.TYPE_KEY_UPDATE_REP:
            validateInitCertRep(message);
            break;
        case PKIBody.TYPE_REVOCATION_REQ:
            validateRevReq(message);
            break;
        case PKIBody.TYPE_REVOCATION_REP:
            validateRevRep(message);
            break;
        case PKIBody.TYPE_CERT_CONFIRM:
            validateCertConfirm(message);
            break;
        case PKIBody.TYPE_CONFIRM:
            validateConfirm(message);
            break;
        case PKIBody.TYPE_POLL_REQ:
            validatePollReq(message);
            break;
        case PKIBody.TYPE_POLL_REP:
            validatePollRep(message);
            break;
        case PKIBody.TYPE_GEN_MSG:
            validateGenMessage(message);
            break;
        case PKIBody.TYPE_GEN_REP:
            validateGenRep(message);
            break;
        case PKIBody.TYPE_ERROR:
        case PKIBody.TYPE_NESTED:
            break;
        default:
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badMessageCheck,
                    MessageDumper.msgTypeAsString(message.getBody())
                            + " not supported");
        }
    }

    /**
     * Validates {@link PKIMessage messages} of type CertConf (Certificate
     * Confirm).
     *
     * @param message
     *            the CMP message to validate
     */
    private void validateCertConfirm(final PKIMessage message) {

        final ASN1Encodable content = message.getBody().getContent();
        assertContentOfType(content, CertConfirmContent.class);
        validateConfirmContent((CertConfirmContent) content);
    }

    /**
     * Validates {@link PKIMessage messages} of type PKIConf (Confirmation).
     *
     * @param message
     *            the CMP message to validate
     */
    private void validateConfirm(final PKIMessage message) {
        final ASN1Encodable content = message.getBody().getContent();
        assertContentOfType(content, PKIConfirmContent.class);
    }

    /**
     * Validates the {@link CertConfirmContent} data structure which is part of
     * a
     * Certificate Confirmation message.<br>
     * <strong>Note:</strong><br>
     * See RFC4210 Section 5.3.18. Certificate Confirmation Content for further
     * details.
     *
     * @param content
     *            the {@link CertConfirmContent} object to validate
     */
    private void validateConfirmContent(final CertConfirmContent content) {
        final CertStatus[] certStatusArray = content.toCertStatusArray();
        assertExactlyOneElement(certStatusArray, PKIFailureInfo.badDataFormat,
                "one cert status reqired");
        final CertStatus certStatus = certStatusArray[0];
        // statusInfo OPTIONAL validate if set
        final PKIStatusInfo status = certStatus.getStatusInfo();
        assertNotNull(status, PKIFailureInfo.addInfoNotAvailable,
                "certStatus.StatusInfo required");
        validateStatusInfo(status);
        assertNotNull(certStatus.getCertReqId(),
                PKIFailureInfo.addInfoNotAvailable, "cert req id is null");
        assertEqual(certStatus.getCertReqId(), ASN1INTEGER_0,
                "CertReqId must be 0");
    }

    /**
     * Validates {@link PKIMessage messages} of type IR, CR and KUR.
     *
     * @param message
     *            the CMP message to validate
     */
    private void validateCrmfCertReq(final PKIMessage message) {
        final ASN1Encodable content = message.getBody().getContent();
        assertContentOfType(content, CertReqMessages.class);
        final Object[] array = ((CertReqMessages) content).toCertReqMsgArray();
        if (array == null || array.length != 1) {
            throw new CmpEnrollmentException(message, interfaceName,
                    PKIFailureInfo.badDataFormat,
                    "exactly one cert req required");
        }
        final CertReqMsg certReqMsg =
                ((CertReqMessages) content).toCertReqMsgArray()[0];
        final CertRequest certReq = certReqMsg.getCertReq();
        final CertTemplate certTemplate = certReq.getCertTemplate();
        if (Objects.isNull(certTemplate.getSubject())) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badCertTemplate, "no subject in template");
        }
        if (!Objects.equals(certReq.getCertReqId(), ASN1INTEGER_0)) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badDataFormat, "CertReqId must be 0");
        }
        final ProofOfPossession popo = certReqMsg.getPopo();
        if (popo == null) {
            final SubjectPublicKeyInfo publicKeyInTemplate =
                    certTemplate.getPublicKey();
            if (publicKeyInTemplate != null
                    && publicKeyInTemplate.getPublicKeyData() != null
                    && publicKeyInTemplate.getPublicKeyData()
                            .getBytes().length > 0) {
                throw new CmpEnrollmentException(message, interfaceName,
                        PKIFailureInfo.badPOP,
                        "public key present in template but POPO missing");
            }
        } else {
            switch (popo.getType()) {
            case ProofOfPossession.TYPE_RA_VERIFIED:
                if (!acceptRaVerified) {
                    throw new CmpEnrollmentException(message, interfaceName,
                            PKIFailureInfo.badPOP,
                            "POPO RaVerified not allowed here");
                }
                break;
            case ProofOfPossession.TYPE_SIGNING_KEY:
                try {
                    // a POPO is still there and maybe re-usable
                    final POPOSigningKey popoSigningKey =
                            (POPOSigningKey) popo.getObject();
                    assertIsNull(popoSigningKey.getPoposkInput(),
                            PKIFailureInfo.badPOP,
                            "PoposkInput must be absent");
                    final SubjectPublicKeyInfo publicKeyInfo =
                            certTemplate.getPublicKey();
                    final PublicKey publicKey = KeyFactory
                            .getInstance(publicKeyInfo.getAlgorithm()
                                    .getAlgorithm().toString(),
                                    CertUtility.BOUNCY_CASTLE_PROVIDER)
                            .generatePublic(new X509EncodedKeySpec(publicKeyInfo
                                    .getEncoded(ASN1Encoding.DER)));
                    final Signature sig = Signature.getInstance(
                            popoSigningKey.getAlgorithmIdentifier()
                                    .getAlgorithm().getId(),
                            CertUtility.BOUNCY_CASTLE_PROVIDER);
                    sig.initVerify(publicKey);
                    sig.update(certReq.getEncoded(ASN1Encoding.DER));
                    if (!sig.verify(popoSigningKey.getSignature().getBytes())) {
                        throw new CmpEnrollmentException(message, interfaceName,
                                PKIFailureInfo.badPOP, "POPO broken");
                    }
                    // POPO still valid, continue to use it
                } catch (final IOException | NoSuchAlgorithmException
                        | InvalidKeyException | InvalidKeySpecException
                        | SignatureException ex) {
                    throw new CmpEnrollmentException(message, interfaceName,
                            PKIFailureInfo.badPOP,
                            "exception while calculating POPO: "
                                    + ex.getLocalizedMessage());
                }
                break;
            default:
                throw new CmpEnrollmentException(message, interfaceName,
                        PKIFailureInfo.badPOP, "unsupported POPO type");
            }
        }
    }

    /**
     * Validates PKIFailureInfo field value, whether it is a valid value.
     *
     * @param failInfo
     *            the value of the failInfo field to validate
     * @throws CmpValidationException
     *             if the given <code>failInfo</code> is not a valid value for
     *             this
     *             field.
     */
    private void validateFailInfo(final DERBitString failInfo) {
        assertNotNull(failInfo, PKIFailureInfo.badDataFormat,
                "fail info is null");
        final int info = failInfo.intValue();
        // test if a positive integer n is a power of 2
        if ((info & info - 1) != 0) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badDataFormat, "invalid fail info: " + info);
        }
    }

    private void validateGenMessage(final PKIMessage message) {
        final GenMsgContent genMessageContent =
                (GenMsgContent) message.getBody().getContent();
        final InfoTypeAndValue[] itav =
                genMessageContent.toInfoTypeAndValueArray();
        assertExactlyOneElement(itav, PKIFailureInfo.badMessageCheck,
                "one InfoTypeAndValue is required");
        assertNotNull(itav[0].getInfoType(), PKIFailureInfo.badMessageCheck,
                "missing InfoType");
    }

    private void validateGenRep(final PKIMessage message) {
        final GenMsgContent genMessageContent =
                (GenMsgContent) message.getBody().getContent();
        final InfoTypeAndValue[] itav =
                genMessageContent.toInfoTypeAndValueArray();
        assertExactlyOneElement(itav, PKIFailureInfo.badMessageCheck,
                "one InfoTypeAndValue is required");
        assertNotNull(itav[0].getInfoType(), PKIFailureInfo.badMessageCheck,
                "missing InfoType");
    }

    /**
     * Validates the {@link PKIHeader header} of the given {@link PKIMessage
     * message}.<br>
     * <strong>Note:</strong><br>
     * See RFC4210 Section 5.1.1. PKI Message Header for further details.
     *
     * @param message
     *            the CMP message to validate
     * @throws Exception
     */
    private void validateHeader(final PKIMessage message) {
        if (message == null) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badDataFormat,
                    "did not get a valid message, message is null");
        }
        final PKIHeader header = message.getHeader();
        final long versionNumber = header.getPvno().longValueExact();
        if (versionNumber != PKIHeader.CMP_2000
                && versionNumber != 3/* PKIHeader.CMP_2021 */) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.unsupportedVersion,
                    "version " + versionNumber + " not supported");
        }
        final ASN1OctetString transactionID = header.getTransactionID();
        if (transactionID == null) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badDataFormat,
                    "mandatory transaction ID missing");
        }
        final ASN1GeneralizedTime messageTime = header.getMessageTime();
        if (messageTime != null) {
            try {
                final long diffTime = messageTime.getDate().getTime() / 1000L
                        - new Date().getTime() / 1000L;
                if (diffTime > allowedTimeDeviationInSeconds
                        || -diffTime > allowedTimeDeviationInSeconds) {
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.badTime,
                            "message time out of allowed range");
                }
            } catch (final ParseException e) {
                throw new CmpValidationException(interfaceName,
                        PKIFailureInfo.timeNotAvailable,
                        "could not parse message time "
                                + e.getLocalizedMessage());
            }
        }
        if (transactionID.getOctets().length < 16) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badRequest, "used transaction ID too short");
        }
        final ASN1OctetString senderNonce = header.getSenderNonce();
        if (senderNonce == null) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badSenderNonce,
                    "mandatory sender nonce missing");
        }
        if (senderNonce.getOctets().length < 16) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badSenderNonce, " sender nonce too short");
        }
        validatePvno(header.getPvno());
        assertNotNull(header.getSender(), PKIFailureInfo.badDataFormat,
                "missing sender");
        // if the "sender" field contain a "NULL" value, the senderKID field
        // MUST hold an identifier
        if (PkiMessageGenerator.NULL_DN.equals(header.getSender())
                && header.getProtectionAlg() != null) {
            assertNotNull(header.getSenderKID(), PKIFailureInfo.badDataFormat,
                    "missing sender KID");
        }
        assertNotNull(header.getRecipient(), PKIFailureInfo.badDataFormat,
                "invalid recipient");
    }

    /**
     * Validates {@link PKIMessage messages} of type IP (Initialization
     * Response)
     * and CP (Certification Response).
     *
     * @param message
     *            the CMP message to validate
     */
    private void validateInitCertRep(final PKIMessage message) {
        final ASN1Encodable content = message.getBody().getContent();
        assertContentOfType(content, CertRepMessage.class);
        validateResponse((CertRepMessage) content);
    }

    private void validateP10CertReq(final PKIMessage message) {
        final PKCS10CertificationRequest p10Request =
                new PKCS10CertificationRequest(
                        (CertificationRequest) message.getBody().getContent());
        try {
            if (!p10Request
                    .isSignatureValid(jcaX509ContentVerifierProviderBuilder
                            .build(p10Request.getSubjectPublicKeyInfo()))) {
                throw new CmpValidationException(interfaceName,
                        PKIFailureInfo.badPOP,
                        "PKCS#10 signature validation failed");
            }
        } catch (OperatorCreationException | PKCSException e) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badPOP,
                    "PKCS#10 signature validation failed: "
                            + e.getLocalizedMessage());
        }

    }

    private void validatePollRep(final PKIMessage message) {
        final PollRepContent content =
                (PollRepContent) message.getBody().getContent();
        assertEqual(content.size(), 1, "exactly one certReqId");
        final ASN1Integer reqIds = content.getCertReqId(0);
        assertEqual(reqIds, new ASN1Integer(0), "certReqId mus be zero");
    }

    private void validatePollReq(final PKIMessage message) {
        final PollReqContent content =
                (PollReqContent) message.getBody().getContent();
        final BigInteger[] reqIds = content.getCertReqIdValues();

        assertExactlyOneElement(reqIds, PKIFailureInfo.badDataFormat,
                "one certReqId reqired");
        assertEqual(reqIds[0], BigInteger.ZERO, "certReqId mus be zero");

    }

    /**
     * Validates the given <code>pvno</code>, a field within the header, to
     * ensure
     * that it is not <code>null</code> and set to <code>2</code> (equivalent to
     * PKIHeader.CMP_2000).
     *
     * @param pvno
     *            the value of the <code>pvno</code> field to validate
     */
    private void validatePvno(final ASN1Integer pvno) {
        assertNotNull(pvno, PKIFailureInfo.unsupportedVersion, "pvno is null");
        assertEqual(pvno.getValue().intValue(), PKIHeader.CMP_2000,
                "invalid pvno");
    }

    /**
     * Validates the {@link CertRepMessage} data structure which is part of a
     * Initialization Response or a Certification Response.<br>
     * <strong>Note:</strong><br>
     * See RFC4210 Section 5.3.4 for further details.
     *
     * @param certRep
     *            the {@link CertRepMessage} object to validate
     */
    private void validateResponse(final CertRepMessage certRep) {
        final CertResponse[] certResponse = certRep.getResponse();
        assertExactlyOneElement(certResponse, PKIFailureInfo.badDataFormat,
                "one cert response required");
        final CertResponse singleCertResponse = certResponse[0];
        final PKIStatusInfo status = singleCertResponse.getStatus();
        final int statusValue = status.getStatus().intValue();
        validateStatusInfo(status);
        final CertifiedKeyPair certifiedKeyPair =
                singleCertResponse.getCertifiedKeyPair();

        // Only one of the failInfo (in PKIStatusInfo) and certificate (in
        // CertifiedKeyPair) fields can be present in each CertResponse
        // (depending on the status)
        if (status.getFailInfo() != null) {
            assertIsNull(certifiedKeyPair, PKIFailureInfo.badDataFormat,
                    "both failInfo and certificate are set");
            // if PKIStatusInfo.status is one of:
            // -- accepted, or
            // -- grantedWithMods,
            // -- then certifiedKeyPair MUST be present and failInfo MUST
            // -- be absent
            if (PKIStatus.GRANTED == statusValue
                    || PKIStatus.GRANTED_WITH_MODS == statusValue) {
                throw new CmpValidationException(interfaceName,
                        PKIFailureInfo.badDataFormat,
                        "fail info in combination with accepted status");
            }

        }
        if (certifiedKeyPair != null) {
            // if PKIStatusInfo.status is:
            // -- rejection
            // -- then certifiedKeyPair MUST be absent and failInfo MUST be
            // -- present and contain appropriate bit settings
            if (PKIStatus.REJECTION == statusValue) {
                throw new CmpValidationException(interfaceName,
                        PKIFailureInfo.badDataFormat,
                        "certificate in combination with rejected status");
            }
            assertNotNull(certifiedKeyPair.getCertOrEncCert(),
                    PKIFailureInfo.badDataFormat, "Certificate is null");
            assertIsNull(status.getFailInfo(), PKIFailureInfo.badDataFormat,
                    "both failInfo and certificate are set");
            assertNotNull(singleCertResponse.getCertReqId(),
                    PKIFailureInfo.badDataFormat, "cert req id is null");
        }
    }

    /**
     * Validates {@link PKIMessage messages} of type RP (Revocation Response).
     *
     * @param message
     *            the CMP message to validate
     */
    private void validateRevRep(final PKIMessage message) {

        final ASN1Encodable content = message.getBody().getContent();
        assertContentOfType(content, RevRepContent.class);
    }

    /**
     * Validates {@link PKIMessage messages} of type RR (Revocation Request).
     *
     * @param message
     *            the CMP message to validate
     */
    private void validateRevReq(final PKIMessage message) {

        final ASN1Encodable content = message.getBody().getContent();
        assertContentOfType(content, RevReqContent.class);
        final RevDetails[] revDetails =
                ((RevReqContent) content).toRevDetailsArray();
        assertExactlyOneElement(revDetails, PKIFailureInfo.addInfoNotAvailable,
                "one revoke detail required");
        final CertTemplate certDetails = revDetails[0].getCertDetails();
        assertNotNull(certDetails.getSerialNumber(),
                PKIFailureInfo.addInfoNotAvailable,
                "missing serial number in template");
        assertNotNull(certDetails.getIssuer(),
                PKIFailureInfo.addInfoNotAvailable,
                "missing issuer in template");
        assertNotNull(revDetails[0].getCrlEntryDetails(),
                PKIFailureInfo.addInfoNotAvailable, "missing crlEntryDetails");
        assertNotNull(
                revDetails[0].getCrlEntryDetails()
                        .getExtension(Extension.reasonCode),
                PKIFailureInfo.addInfoNotAvailable,
                "missing crlEntryDetails.reason");
        // assertEqual(certDetails.getVersion(), 2, "invalid version");
    }

    /**
     * Validates {@link PKIStatusInfo} field value, whether it is a valid value.
     *
     * @param status
     *            the value of the {@link PKIStatusInfo} field to validate
     * @throws CmpValidationException
     *             if the given <code>statusInfo</code> is not a valid value for
     *             this field.
     */
    private void validateStatusInfo(final PKIStatusInfo status) {
        assertNotNull(status, PKIFailureInfo.badDataFormat,
                "PKIStatusInfo is null");
        assertNotNull(status.getStatus(), PKIFailureInfo.badDataFormat,
                "PKIStatusInfo.status is null");
        final int value = status.getStatus().intValue();
        if (value < PKIStatus.GRANTED || value > PKIStatus.KEY_UPDATE_WARNING) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badDataFormat,
                    "invalid PKIStatus info: " + status);
        }
        if (status.getFailInfo() != null) {
            validateFailInfo(status.getFailInfo());
        }

    }

}
