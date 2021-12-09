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

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.cmp.PKIMessage;

import com.siemens.pki.lightweightcmpra.config.xmlparser.CMPCREDENTIALS;
import com.siemens.pki.lightweightcmpra.config.xmlparser.COAPSERVERCONFIGURATION;
import com.siemens.pki.lightweightcmpra.config.xmlparser.DOWNSTREAMCONFIGURATION;
import com.siemens.pki.lightweightcmpra.config.xmlparser.HTTPSERVERCONFIGURATION;
import com.siemens.pki.lightweightcmpra.config.xmlparser.MESSAGEHANDLERCONFIGURATION;
import com.siemens.pki.lightweightcmpra.config.xmlparser.OFFLINEFILESERVERCONFIGURATION;
import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;
import com.siemens.pki.lightweightcmpra.msgvalidation.BaseCmpException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;
import com.siemens.pki.lightweightcmpra.msgvalidation.InputValidator;
import com.siemens.pki.lightweightcmpra.server.CmpCoapServer;
import com.siemens.pki.lightweightcmpra.server.CmpHttpServer;
import com.siemens.pki.lightweightcmpra.server.InternalMessageHandlerStub;
import com.siemens.pki.lightweightcmpra.server.OfflineFileServer;
import com.siemens.pki.lightweightcmpra.util.MsgProcessingAdapter;

/**
 * representation of a downstream interface of a RA
 *
 */
public abstract class BasicDownstream {

    protected static final String INTERFACE_NAME = "downstream";
    private final InputValidator inputValidator;
    protected final MsgOutputProtector outputProtector;

    /**
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     *
     * @param acceptRaVerified
     *            if raVerfied is acceptable in IR, CR, KUR
     * @param supportedMessageTypes
     *            acceptable message types
     * @throws Exception
     *             in case of general error
     */
    public BasicDownstream(final DOWNSTREAMCONFIGURATION config,
            final boolean acceptRaVerified,
            final Integer... supportedMessageTypes) throws Exception {
        final CMPCREDENTIALS cmpCredentials = config.getCmpCredentials();
        inputValidator = new InputValidator(INTERFACE_NAME, acceptRaVerified,
                cmpCredentials.getIn(), supportedMessageTypes);
        outputProtector = new MsgOutputProtector(cmpCredentials.getOut());
        final DownstreamNestingFunctionIF nestingFunction =
                config.getNestedEndpointCredentials() != null
                        ? new DownstreamNestingFunction(
                                config.getNestedEndpointCredentials(),
                                this::handleInputMessage)
                        : DownstreamNestingFunctionIF
                                .get_NO_NESTING(this::handleInputMessage);
        final HTTPSERVERCONFIGURATION cmpHttpServer = config.getCmpHttpServer();
        if (cmpHttpServer != null) {
            CmpHttpServer.createCmpHttpServerFromConfig(cmpHttpServer,
                    MsgProcessingAdapter
                            .adaptMsgHandlerToInputStreamToByteFunction(
                                    INTERFACE_NAME, nestingFunction));
        }
        final COAPSERVERCONFIGURATION coapServer = config.getCoapServer();
        if (coapServer != null) {
            new CmpCoapServer(coapServer,
                    MsgProcessingAdapter.adaptMsgHandlerToByteToByteFunction(
                            INTERFACE_NAME, nestingFunction));
        }
        final MESSAGEHANDLERCONFIGURATION messageHandler =
                config.getMessageHandler();
        if (messageHandler != null) {
            new InternalMessageHandlerStub(messageHandler,
                    MsgProcessingAdapter
                            .adaptMsgHandlerToInputStreamToByteFunction(
                                    INTERFACE_NAME, nestingFunction));
        }
        final OFFLINEFILESERVERCONFIGURATION offlineFileServer =
                config.getOfflineFileServer();
        if (offlineFileServer != null) {
            new OfflineFileServer(offlineFileServer, nestingFunction);
        }
    }

    /**
     * message handler implementation
     *
     * @param in
     *            received message
     * @return message to respond
     */
    protected PKIMessage handleInputMessage(final PKIMessage in) {
        try {
            try {
                inputValidator.validate(in);
                return handleValidatedInputMessage(in);
            } catch (final BaseCmpException e) {
                return outputProtector.generateAndProtectMessage(
                        PkiMessageGenerator.buildRespondingHeaderProvider(in),
                        e.asErrorBody());
            }
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Exception ex) {
            throw new CmpProcessingException(INTERFACE_NAME, ex);
        }
    }

    abstract protected PKIMessage handleValidatedInputMessage(
            final PKIMessage in);

}
