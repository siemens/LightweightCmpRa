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
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIMessages;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;

import com.siemens.pki.lightweightcmpra.config.xmlparser.NESTEDENDPOINTCONFIGURATION;
import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.msggeneration.HeaderProvider;
import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpValidationException;
import com.siemens.pki.lightweightcmpra.msgvalidation.InputValidator;
import com.siemens.pki.lightweightcmpra.protection.SignatureBasedProtection;

/**
 * upstream interface for nested message processing
 *
 */
public class UpstreamNestingFunction implements UpstreamNestingFunctionIF {

    class SentNestedMessageSummary {
        final byte[] senderNonce;
        final PKIMessage[] requests;

        public SentNestedMessageSummary(final PKIMessage[] requests,
                final byte[] senderNonce) {
            this.requests = requests;
            this.senderNonce = senderNonce;
        }

    }

    /**
     * randomness is important
     */
    private static final String INTERFACE_NAME = "nested upstream";

    private final SignatureBasedProtection protectionProvider;

    private final InputValidator inputValidator;

    private final GeneralName usedRecipient;

    private final Map<BEROctetString, SentNestedMessageSummary> pendingTransactionMap =
            new ConcurrentHashMap<>();

    /**
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     *
     * @throws Exception
     *             in case of error
     */
    UpstreamNestingFunction(final NESTEDENDPOINTCONFIGURATION config)
            throws Exception {
        this.protectionProvider = new SignatureBasedProtection(config.getOut());
        this.inputValidator = new InputValidator(INTERFACE_NAME, config.getIn(),
                PKIBody.TYPE_NESTED);
        this.usedRecipient =
                new GeneralName(new X500Name(config.getRecipient()));
    }

    private PKIMessage generatePkiErrrorAboutMissingResponse(
            final PKIMessage sentRequest) {
        try {
            return PkiMessageGenerator.generateAndProtectMessage(
                    PkiMessageGenerator
                            .buildRespondingHeaderProvider(sentRequest),
                    protectionProvider,
                    PkiMessageGenerator.generateErrorBody(
                            PKIFailureInfo.systemUnavail,
                            "request or response lost in transmission"));
        } catch (final Exception e) {
            throw new CmpProcessingException(INTERFACE_NAME, e);
        }
    }

    /**
     * return a requests/responses function doing the whole nesting stuff for
     * multiple requests and related responses
     *
     * @param wrappedFunction
     *            function used for forwarding and receiving the nested request
     *            and response
     * @return the processing function
     */
    @Override
    public Function<PKIMessage[], PKIMessage[]> getAsArrayWrappingFunction(
            final Function<PKIMessage, PKIMessage> wrappedFunction) {
        return msgsToWrap -> unwrapResponses(
                wrappedFunction.apply(wrapRequests(msgsToWrap)));
    }

    /**
     * return a request/response function doing the whole nesting stuff for one
     * request and one related response
     *
     * @param wrappedFunction
     *            function used for processing the nested request and response
     *            for only one request and response
     * @return the processing function
     */
    @Override
    public Function<PKIMessage, PKIMessage> getAsWrappingFunction(
            final Function<PKIMessage, PKIMessage> wrappedFunction) {
        return msgsToWrap -> unwrapResponses(
                wrappedFunction.apply(wrapRequests(msgsToWrap)))[0];
    }

    /**
     * unwrap a nested response
     *
     * @param nestedResponse
     *            nested {@link PKIMessage} to unwrap
     * @return formerly wrapped messages
     * @throws CmpProcessingException
     *             in case of invalid (type, protection, header) nestedResponse
     */
    @Override
    public PKIMessage[] unwrapResponses(final PKIMessage nestedResponse) {
        inputValidator.validate(nestedResponse);
        final PKIHeader nestedResponseHeader = nestedResponse.getHeader();
        final ASN1OctetString transactionID =
                nestedResponseHeader.getTransactionID();
        final SentNestedMessageSummary relatedSentMessage =
                pendingTransactionMap.remove(transactionID);
        if (relatedSentMessage == null) {
            throw new CmpValidationException(INTERFACE_NAME,
                    PKIFailureInfo.badMessageCheck,
                    "message with spuriuos transactionId " + transactionID
                            + " received");
        }
        final ASN1OctetString recipNonce = nestedResponseHeader.getRecipNonce();
        if (recipNonce == null || !Arrays.equals(relatedSentMessage.senderNonce,
                recipNonce.getOctets())) {
            throw new CmpValidationException(INTERFACE_NAME,
                    PKIFailureInfo.badRecipientNonce,
                    "recipient nonce mismatch");
        }
        final PKIMessage[] unwrappedResponses =
                ((PKIMessages) nestedResponse.getBody().getContent())
                        .toPKIMessageArray();
        final Map<ASN1OctetString, PKIMessage> mapOfResponses =
                Arrays.stream(unwrappedResponses).collect(Collectors.toMap(
                        msg -> msg.getHeader().getTransactionID(), msg -> msg));
        final List<PKIMessage> orderedResponses = Arrays
                .stream(relatedSentMessage.requests)
                .map(sentRequest -> mapOfResponses.computeIfAbsent(
                        sentRequest.getHeader().getTransactionID(),
                        missingTransactionId -> generatePkiErrrorAboutMissingResponse(
                                sentRequest)))
                .collect(Collectors.toList());
        // Superfluous messages are silently dropped
        return orderedResponses
                .toArray(new PKIMessage[orderedResponses.size()]);
    }

    /**
     *
     * @param requests
     *            requests to wrap in a nested message
     * @return {@link PKIMessage} of Type {@link PKIBody.TYPE_NESTED}
     * @throws Exception
     *             in case of error
     */
    @Override
    public PKIMessage wrapRequests(final PKIMessage... requests) {
        final BEROctetString transactionId =
                new BEROctetString(CertUtility.generateRandomBytes(20));
        final byte[] senderNonce = CertUtility.generateRandomBytes(20);
        int maxPvno = PKIHeader.CMP_2000;
        for (final PKIMessage aktRequest : requests) {
            final int aktPvno =
                    aktRequest.getHeader().getPvno().intValueExact();
            if (aktPvno > maxPvno) {
                maxPvno = aktPvno;
            }
        }
        final int pvno = maxPvno;
        final HeaderProvider headerProvider = new HeaderProvider() {

            @Override
            public InfoTypeAndValue[] getGeneralInfo() {
                return null;
            }

            @Override
            public ASN1GeneralizedTime getMessageTime() {
                return new DERGeneralizedTime(new Date());
            }

            @Override
            public int getPvno() {
                return pvno;
            }

            @Override
            public GeneralName getRecipient() {
                return usedRecipient;
            }

            @Override
            public byte[] getRecipNonce() {
                return null;
            }

            @Override
            public GeneralName getSender() {
                return null;
            }

            @Override
            public byte[] getSenderNonce() {
                return senderNonce;
            }

            @Override
            public ASN1OctetString getTransactionID() {
                return transactionId;
            }
        };
        PKIMessage ret;
        try {
            ret = PkiMessageGenerator.generateAndProtectMessage(headerProvider,
                    protectionProvider, new PKIBody(PKIBody.TYPE_NESTED,
                            new PKIMessages(requests)));
        } catch (final Exception e) {
            throw new CmpProcessingException(INTERFACE_NAME, e);
        }
        if (pendingTransactionMap.put(transactionId,
                new SentNestedMessageSummary(requests, senderNonce)) != null) {
            throw new CmpProcessingException(INTERFACE_NAME,
                    PKIFailureInfo.systemUnavail, "insufficient PRNG");
        }
        return ret;
    }

}
