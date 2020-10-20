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
package com.siemens.pki.lightweightcmpra.client.offline;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;
import com.siemens.pki.lightweightcmpra.msgprocessing.MsgOutputProtector;
import com.siemens.pki.lightweightcmpra.msgprocessing.UpstreamNestingFunctionIF;
import com.siemens.pki.lightweightcmpra.msgvalidation.BaseCmpException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

/**
 * offline upstream interface with support for polling
 *
 */
abstract public class OfflineClient
        implements Function<PKIMessage, PKIMessage> {

    private static final String INTERFACE_NAME = "offline upstream";

    // placeholder for not yet received response
    private static final PKIMessage RESPONSE_TO_MESSAGE_NOT_YET_RECEIVED =
            new PKIMessage(null, null);

    private static final Logger LOGGER =
            LoggerFactory.getLogger(OfflineClient.class);

    private final Map<ASN1OctetString, PKIMessage> transactionResponseMap =
            new ConcurrentHashMap<>();

    private final MsgOutputProtector localResponseProtector;

    private final int checkAfterTime;

    private final UpstreamNestingFunctionIF nestingFunction;

    /**
     * @param localResponseProtector
     *            protector used to protect locally generated errors an
     *            responses
     * @param checkAfterTime
     *            checkAfterTime used in responded ROLLREP's
     * @param nestingFunction
     *            function used for adding protection (nesting)
     */
    public OfflineClient(final MsgOutputProtector localResponseProtector,
            final int checkAfterTime,
            final UpstreamNestingFunctionIF nestingFunction) {
        this.localResponseProtector = localResponseProtector;
        this.checkAfterTime = checkAfterTime;
        this.nestingFunction = nestingFunction;
    }

    @Override
    public PKIMessage apply(final PKIMessage msg) {
        try {
            final int bodyType = msg.getBody().getType();
            switch (bodyType) {
            case PKIBody.TYPE_INIT_REQ:
            case PKIBody.TYPE_CERT_REQ:
            case PKIBody.TYPE_KEY_UPDATE_REQ:
                return forwardRequest(msg);
            case PKIBody.TYPE_POLL_REQ:
                return respondToPolling(msg);
            case PKIBody.TYPE_CERT_CONFIRM:
                return respondToCertConfirm(msg);
            default:
                throw new CmpProcessingException(INTERFACE_NAME,
                        PKIFailureInfo.badRequest,
                        "request with body type " + bodyType
                                + " not supported by offline upstream interface");
            }
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Exception ex) {
            throw new CmpProcessingException(ex);
        }
    }

    /**
     * protect and forward message to external upstream interface
     */
    private PKIMessage forwardRequest(final PKIMessage msg) throws Exception {
        final ASN1OctetString transactionID =
                msg.getHeader().getTransactionID();
        if (transactionResponseMap.putIfAbsent(transactionID,
                RESPONSE_TO_MESSAGE_NOT_YET_RECEIVED) != null) {
            throw new CmpProcessingException(INTERFACE_NAME,
                    PKIFailureInfo.transactionIdInUse,
                    "transactionId " + transactionID
                            + " was already useded for another request");
        }
        final PKIMessage wrappedRequests = nestingFunction.wrapRequests(msg);
        // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't enabled
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send msg:\n"
                    + MessageDumper.dumpPkiMessage(wrappedRequests));
        }
        forwardRequestToInterface(wrappedRequests);
        return localResponseProtector.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(msg),
                PkiMessageGenerator.generateIpCpKupBodyWithWaiting(
                        msg.getBody().getType() + 1));
    }

    /**
     * forward protected message asynchronously to the upstream interface
     *
     * @param msg
     *            message to send
     * @throws IOException
     *             in case of error
     */
    abstract protected void forwardRequestToInterface(final PKIMessage msg)
            throws IOException;

    private PKIMessage respondToCertConfirm(final PKIMessage msg)
            throws Exception {
        // TODO currently we confirm everything
        transactionResponseMap.remove(msg.getHeader().getTransactionID());
        return localResponseProtector.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(msg),
                PkiMessageGenerator.generatePkiConfirmBody());
    }

    /**
     * handle POLLREQ
     */
    private PKIMessage respondToPolling(final PKIMessage msg) throws Exception {
        final ASN1OctetString transactionID =
                msg.getHeader().getTransactionID();
        final PKIMessage response = transactionResponseMap.get(transactionID);
        if (response == null) {
            throw new CmpProcessingException(INTERFACE_NAME,
                    PKIFailureInfo.badRequest,
                    "no request for transactionId " + transactionID + " known");
        }
        if (response == RESPONSE_TO_MESSAGE_NOT_YET_RECEIVED) {
            return localResponseProtector.generateAndProtectMessage(
                    PkiMessageGenerator.buildRespondingHeaderProvider(msg),
                    PkiMessageGenerator.generatePollRep(checkAfterTime));
        }
        return localResponseProtector.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(msg),
                response.getBody(), Arrays.asList(response.getExtraCerts()));
    }

    /**
     * callback from messages received from upstream interface
     *
     * @param msg
     *            received message
     */
    protected void responseFromInterfaceReceived(
            final PKIMessage maybeNestedResponse) {
        // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't enabled
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got msg:\n"
                    + MessageDumper.dumpPkiMessage(maybeNestedResponse));
        }
        for (final PKIMessage msg : nestingFunction
                .unwrapResponses(maybeNestedResponse)) {
            final ASN1OctetString transactionID =
                    msg.getHeader().getTransactionID();
            final PKIMessage formerlyStoredResponse =
                    transactionResponseMap.put(transactionID, msg);
            if (formerlyStoredResponse == null) {
                LOGGER.warn("got unwanted response for transactionID "
                        + transactionID);
                transactionResponseMap.remove(transactionID);
                continue;
            }
            if (formerlyStoredResponse != RESPONSE_TO_MESSAGE_NOT_YET_RECEIVED) {
                LOGGER.warn("got repeated response for transactionID "
                        + transactionID);
            }
        }
    }

}
