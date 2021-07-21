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

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.siemens.pki.lightweightcmpra.msgvalidation.BaseCmpException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpValidationException;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

/**
 * class for tracking all important states of a CMP transaction
 *
 */
public class TransactionStateTracker {
    /**
     * current state of a transaction
     *
     */
    enum LastTransactionState {
        INITIAL_STATE, REQUEST_SENT, CERTIFICATE_RECEIVED, CERTIFICATE_CONFIRMEND, CONFIRM_CONFIRMED, POLLING, REVOCATION_SENT, REVOCATION_CONFIRMED, GENM_RECEIVED, GENREP_RETURNED, IN_ERROR_STATE
    }

    /**
     * handler for one transaction identified by a transactionId
     *
     */
    class SingleTransactionStateHandler {
        LastTransactionState lastTransactionState =
                LastTransactionState.INITIAL_STATE;
        private ASN1OctetString lastSenderNonce;
        private byte digestToConfirm[];
        private boolean implicitConfirmGranted = true;
        private SubjectPublicKeyInfo requestedPublicKey;

        private boolean grantsImplicitConfirm(final PKIMessage msg) {
            final InfoTypeAndValue[] generalInfo =
                    msg.getHeader().getGeneralInfo();
            if (generalInfo == null) {
                return false;
            }
            for (final InfoTypeAndValue aktGenInfo : generalInfo) {
                if (aktGenInfo.getInfoType()
                        .equals(CMPObjectIdentifiers.it_implicitConfirm)) {
                    return true;
                }
            }
            return false;
        }

        private void handleCertResponse(final PKIMessage msg) {
            implicitConfirmGranted &= grantsImplicitConfirm(msg);
            try {
                final Certificate enrolledCertificate =
                        ((CertRepMessage) msg.getBody().getContent())
                                .getResponse()[0].getCertifiedKeyPair()
                                        .getCertOrEncCert().getCertificate()
                                        .getX509v3PKCert();
                final DigestCalculator dc = digestProvider.get(digestFinder
                        .find(enrolledCertificate.getSignatureAlgorithm()));
                dc.getOutputStream().write(enrolledCertificate.getEncoded());
                digestToConfirm = dc.getDigest();
                final SubjectPublicKeyInfo enrolledPublicKey =
                        enrolledCertificate.getSubjectPublicKeyInfo();
                if (!Arrays.equals(requestedPublicKey.getEncoded(),
                        enrolledPublicKey.getEncoded())) {
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.badMessageCheck,
                            "wrong public key in cert response");
                }
                lastTransactionState =
                        LastTransactionState.CERTIFICATE_RECEIVED;
            } catch (final BaseCmpException ex) {
                throw ex;
            } catch (final Exception e) {
                lastTransactionState = LastTransactionState.IN_ERROR_STATE;
                throw new CmpProcessingException(interfaceName,
                        PKIFailureInfo.badMessageCheck,
                        "could not calculate certificate hash:"
                                + e.getLocalizedMessage() + " for "
                                + MessageDumper.msgAsShortString(msg));
            }
        }

        private boolean isCertConfirm(final PKIMessage msg) {
            return msg.getBody().getType() == PKIBody.TYPE_CERT_CONFIRM;
        }

        private boolean isCertRequest(final PKIMessage msg) {
            switch (msg.getBody().getType()) {
            case PKIBody.TYPE_CERT_REQ:
            case PKIBody.TYPE_INIT_REQ:
            case PKIBody.TYPE_KEY_UPDATE_REQ:
            case PKIBody.TYPE_P10_CERT_REQ:
                return true;
            default:
                return false;
            }
        }

        private boolean isCertResponse(final PKIMessage msg) {
            switch (msg.getBody().getType()) {
            case PKIBody.TYPE_CERT_REP:
            case PKIBody.TYPE_INIT_REP:
            case PKIBody.TYPE_KEY_UPDATE_REP:
                return true;
            default:
                return false;
            }
        }

        private boolean isCertResponseWithWaitingIndication(
                final PKIMessage msg) {
            try {
                return ((CertRepMessage) msg.getBody().getContent())
                        .getResponse()[0].getStatus().getStatus()
                                .intValue() == PKIStatus.WAITING;
            } catch (final Exception ex) {
                return false;
            }
        }

        private boolean isConfirmConfirm(final PKIMessage msg) {
            return msg.getBody().getType() == PKIBody.TYPE_CONFIRM;
        }

        private boolean isError(final PKIMessage msg) {
            switch (msg.getBody().getType()) {
            case PKIBody.TYPE_CERT_REP:
            case PKIBody.TYPE_INIT_REP:
            case PKIBody.TYPE_KEY_UPDATE_REP: {
                final CertResponse[] responses =
                        ((CertRepMessage) msg.getBody().getContent())
                                .getResponse();
                if (responses != null && responses.length == 1
                        && responses[0].getStatus() != null) {
                    switch (responses[0].getStatus().getStatus().intValue()) {
                    case PKIStatus.GRANTED:
                    case PKIStatus.GRANTED_WITH_MODS:
                    case PKIStatus.WAITING:
                        return false;
                    }
                    return true;
                }
                return false;
            }
            case PKIBody.TYPE_CERT_CONFIRM: {
                final CertStatus[] responses =
                        ((CertConfirmContent) msg.getBody().getContent())
                                .toCertStatusArray();
                if (responses != null && responses.length == 1
                        && responses[0].getStatusInfo() != null) {
                    switch (responses[0].getStatusInfo().getStatus()
                            .intValue()) {
                    case PKIStatus.GRANTED:
                    case PKIStatus.GRANTED_WITH_MODS:
                        return false;
                    }
                    return true;
                }
                return false;
            }

            case PKIBody.TYPE_ERROR:
                return true;
            }
            return false;
        }

        private boolean isFirstResponse(final PKIMessage msg) {
            return isCertResponse(msg) || isPollResponse(msg);
        }

        private boolean isGenMessage(final PKIMessage msg) {
            return msg.getBody().getType() == PKIBody.TYPE_GEN_MSG;
        }

        private boolean isGenRep(final PKIMessage msg) {
            return msg.getBody().getType() == PKIBody.TYPE_GEN_REP;
        }

        private boolean isP10CertRequest(final PKIMessage msg) {
            return msg.getBody().getType() == PKIBody.TYPE_P10_CERT_REQ;
        }

        private boolean isPollRequest(final PKIMessage msg) {
            return msg.getBody().getType() == PKIBody.TYPE_POLL_REQ;
        }

        private boolean isPollResponse(final PKIMessage msg) {
            return msg.getBody().getType() == PKIBody.TYPE_POLL_REP;
        }

        private boolean isRevocationRequest(final PKIMessage msg) {
            return msg.getBody().getType() == PKIBody.TYPE_REVOCATION_REQ;
        }

        private boolean isRevocationResponse(final PKIMessage msg) {
            return msg.getBody().getType() == PKIBody.TYPE_REVOCATION_REP;
        }

        private boolean isSecondRequest(final PKIMessage msg) {
            switch (msg.getBody().getType()) {
            case PKIBody.TYPE_POLL_REQ:
            case PKIBody.TYPE_CERT_CONFIRM:
                return true;
            default:
                return false;
            }
        }

        /**
         * the main state machine
         *
         * @param msg
         *            message to process
         * @throws {@link
         *             CmpProcessingException} in case
         *             of error
         */
        void trackMessage(final PKIMessage msg) {
            if (isError(msg)) {
                lastTransactionState = LastTransactionState.IN_ERROR_STATE;
                return;
            }
            if (isFirstResponse(msg)) {
                lastSenderNonce = msg.getHeader().getSenderNonce();
            } else if (isSecondRequest(msg)) {
                if (!Objects.equals(lastSenderNonce,
                        msg.getHeader().getRecipNonce())) {
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.badRecipientNonce,
                            "sender/recipient nonce mismatch for "
                                    + MessageDumper.msgAsShortString(msg));
                }
            }
            switch (lastTransactionState) {
            case IN_ERROR_STATE:
                throw new CmpValidationException(interfaceName,
                        PKIFailureInfo.transactionIdInUse,
                        "transaction already in error state");
            case INITIAL_STATE:
                if (isGenMessage(msg)) {
                    lastTransactionState = LastTransactionState.GENM_RECEIVED;
                    return;
                }
                if (isRevocationRequest(msg)) {
                    lastTransactionState = LastTransactionState.REVOCATION_SENT;
                    return;
                }
                if (!isCertRequest(msg)) {
                    lastTransactionState = LastTransactionState.IN_ERROR_STATE;
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.transactionIdInUse,
                            "transaction does not start with a request for "
                                    + MessageDumper.msgAsShortString(msg));
                }
                if (isP10CertRequest(msg)) {
                    requestedPublicKey =
                            ((CertificationRequest) msg.getBody().getContent())
                                    .getCertificationRequestInfo()
                                    .getSubjectPublicKeyInfo();
                } else {
                    requestedPublicKey =
                            ((CertReqMessages) msg.getBody().getContent())
                                    .toCertReqMsgArray()[0].getCertReq()
                                            .getCertTemplate().getPublicKey();
                }
                implicitConfirmGranted &= grantsImplicitConfirm(msg);
                lastTransactionState = LastTransactionState.REQUEST_SENT;
                return;
            case REQUEST_SENT:
                if (isCertRequest(msg)) {
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.transactionIdInUse,
                            "second request seen in transaction for "
                                    + MessageDumper.msgAsShortString(msg));
                }
                if (!isCertResponse(msg)) {
                    lastTransactionState = LastTransactionState.IN_ERROR_STATE;
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.badMessageCheck,
                            "request was not answered by cert response for "
                                    + MessageDumper.msgAsShortString(msg));
                }
                if (isCertResponseWithWaitingIndication(msg)) {
                    lastTransactionState = LastTransactionState.POLLING;
                    return;
                }
                handleCertResponse(msg);
                return;
            case POLLING:
                if (isPollRequest(msg)) {
                    return;
                }
                if (isPollResponse(msg)) {
                    return;
                }
                if (!isCertResponse(msg)) {
                    lastTransactionState = LastTransactionState.IN_ERROR_STATE;
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.badMessageCheck,
                            "request was not answered by cert response for "
                                    + MessageDumper.msgAsShortString(msg));
                }
                handleCertResponse(msg);
                return;
            case CERTIFICATE_RECEIVED:
                if (!isCertConfirm(msg)) {
                    lastTransactionState = LastTransactionState.IN_ERROR_STATE;
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.badMessageCheck,
                            "response was not answered with confirmation for "
                                    + MessageDumper.msgAsShortString(msg));

                }
                if (!Arrays.equals(digestToConfirm,
                        ((CertConfirmContent) msg.getBody().getContent())
                                .toCertStatusArray()[0].getCertHash()
                                        .getOctets())) {
                    lastTransactionState = LastTransactionState.IN_ERROR_STATE;
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.badCertId,
                            "wrong hash in cert confirmation for "
                                    + MessageDumper.msgAsShortString(msg));
                }
                lastTransactionState =
                        LastTransactionState.CERTIFICATE_CONFIRMEND;
                return;
            case CERTIFICATE_CONFIRMEND:
                if (!isConfirmConfirm(msg)) {
                    lastTransactionState = LastTransactionState.IN_ERROR_STATE;
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.badMessageCheck,
                            "cert confirm was not answered with pki confirm for "
                                    + MessageDumper.msgAsShortString(msg));
                }
                lastTransactionState = LastTransactionState.CONFIRM_CONFIRMED;
                return;
            case REVOCATION_SENT:
                if (!isRevocationResponse(msg)) {
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.transactionIdInUse,
                            "transaction in wrong state for "
                                    + MessageDumper.msgAsShortString(msg));
                }
                lastTransactionState =
                        LastTransactionState.REVOCATION_CONFIRMED;
                return;
            case GENM_RECEIVED:
                if (!isGenRep(msg)) {
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.transactionIdInUse,
                            "transaction in wrong state for "
                                    + MessageDumper.msgAsShortString(msg));
                }
                lastTransactionState = LastTransactionState.GENREP_RETURNED;
                return;
            default:
                throw new CmpValidationException(interfaceName,
                        PKIFailureInfo.transactionIdInUse,
                        "transaction in wrong state for "
                                + MessageDumper.msgAsShortString(msg));
            }
        }
    }

    private final DefaultDigestAlgorithmIdentifierFinder digestFinder =
            new DefaultDigestAlgorithmIdentifierFinder();

    private final DigestCalculatorProvider digestProvider =
            new JcaDigestCalculatorProviderBuilder().build();

    private final Map<ASN1OctetString, SingleTransactionStateHandler> handlerMap =
            new ConcurrentHashMap<>();

    private final String interfaceName;

    TransactionStateTracker(final String interfaceName)
            throws OperatorCreationException {
        this.interfaceName = interfaceName;

    }

    /**
     * track state of a transaction related to a specific incoming message
     *
     * @param msg
     *            message to track
     * @throws {@link
     *             CmpProcessingException} in case
     *             of error
     */
    synchronized void trackMessage(final PKIMessage msg) {
        handlerMap
                .computeIfAbsent(msg.getHeader().getTransactionID(),
                        x -> new SingleTransactionStateHandler())
                .trackMessage(msg);
    }

}
