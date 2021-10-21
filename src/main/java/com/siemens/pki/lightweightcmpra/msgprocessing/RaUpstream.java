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

import java.util.Objects;
import java.util.function.Function;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.client.offline.FileOfflineClient;
import com.siemens.pki.lightweightcmpra.client.online.ClientSession;
import com.siemens.pki.lightweightcmpra.config.xmlparser.CMPCREDENTIALS;
import com.siemens.pki.lightweightcmpra.config.xmlparser.HTTPCLIENTCONFIGURATION;
import com.siemens.pki.lightweightcmpra.config.xmlparser.NESTEDENDPOINTCONFIGURATION;
import com.siemens.pki.lightweightcmpra.config.xmlparser.OFFLINEFILECLIENTCONFIGURATION;
import com.siemens.pki.lightweightcmpra.config.xmlparser.UPSTREAMCONFIGURATION;
import com.siemens.pki.lightweightcmpra.msgvalidation.BaseCmpException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpValidationException;
import com.siemens.pki.lightweightcmpra.msgvalidation.InputValidator;

/**
 * representation of an upstream interface of a RA
 *
 */
class RaUpstream implements Function<PKIMessage, PKIMessage> {

    private static final String INTERFACE_NAME = "upstream";
    private static final Logger LOGGER =
            LoggerFactory.getLogger(RaUpstream.class);
    private final Function<PKIMessage, PKIMessage> upstreamMsgHandler;
    private final InputValidator inputValidator;

    private final MsgOutputProtector outputProtector;
    private final boolean forwardMessage;

    /**
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @throws Exception
     *             in case of error
     */
    RaUpstream(final UPSTREAMCONFIGURATION config) throws Exception {
        final CMPCREDENTIALS cmpCredentials = config.getCmpCredentials();
        inputValidator = new InputValidator(INTERFACE_NAME, false,
                cmpCredentials.getIn(), PKIBody.TYPE_INIT_REP,
                PKIBody.TYPE_CERT_REP, PKIBody.TYPE_KEY_UPDATE_REP,
                PKIBody.TYPE_POLL_REP, PKIBody.TYPE_CONFIRM,
                PKIBody.TYPE_REVOCATION_REP, PKIBody.TYPE_GEN_MSG,
                PKIBody.TYPE_GEN_REP, PKIBody.TYPE_ERROR);
        outputProtector = new MsgOutputProtector(cmpCredentials.getOut());

        forwardMessage = "forward".equalsIgnoreCase(
                config.getCmpCredentials().getOut().getReprotectMode());
        final HTTPCLIENTCONFIGURATION cmpHttpClient = config.getCmpHttpClient();
        final NESTEDENDPOINTCONFIGURATION nestedEndpointCredentials =
                config.getNestedEndpointCredentials();
        final UpstreamNestingFunctionIF nestingFunction =
                nestedEndpointCredentials != null
                        ? new UpstreamNestingFunction(nestedEndpointCredentials)
                        : UpstreamNestingFunctionIF.NO_NESTING;
        if (cmpHttpClient != null) {
            upstreamMsgHandler = ClientSession.createClientSessionFromConfig(
                    cmpHttpClient, nestingFunction);
        } else {
            final OFFLINEFILECLIENTCONFIGURATION offlineFileClient =
                    config.getOfflineFileClient();
            if (offlineFileClient != null) {
                upstreamMsgHandler = new FileOfflineClient(offlineFileClient,
                        outputProtector, nestingFunction);
            } else {
                throw new IllegalArgumentException(
                        "missing client in upstream configuration");
            }
        }
    }

    @Override
    public PKIMessage apply(final PKIMessage in) {

        try {
            final PKIMessage sentMessage = forwardMessage
                    || in.getBody().getType() == PKIBody.TYPE_KEY_UPDATE_REQ
                            ? in // never re-protect a KUR
                            : outputProtector.protectAndForwardMessage(in,
                                    null);
            final PKIMessage receivedMessage =
                    upstreamMsgHandler.apply(sentMessage);

            inputValidator.validate(receivedMessage);
            final PKIHeader inHeader = in.getHeader();
            final PKIHeader recHeader = receivedMessage.getHeader();
            if (!Objects.equals(inHeader.getTransactionID(),
                    recHeader.getTransactionID())) {
                throw new CmpValidationException(INTERFACE_NAME,
                        PKIFailureInfo.badMessageCheck,
                        "transaction ID mismatch on upstream");
            }
            if (!Objects.equals(inHeader.getSenderNonce(),
                    recHeader.getRecipNonce())) {
                throw new CmpValidationException(INTERFACE_NAME,
                        PKIFailureInfo.badRecipientNonce,
                        "nonce mismatch on upstream");
            }
            return receivedMessage;
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Exception ex) {
            LOGGER.error("exception at upstream interface", ex);
            throw new CmpProcessingException(INTERFACE_NAME,
                    PKIFailureInfo.systemFailure, ex);
        }
    }
}
