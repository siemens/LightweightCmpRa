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

import java.util.function.Function;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIMessages;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.config.xmlparser.NESTEDENDPOINTCONFIGURATION;
import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;
import com.siemens.pki.lightweightcmpra.msgvalidation.BaseCmpException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpValidationException;
import com.siemens.pki.lightweightcmpra.msgvalidation.InputValidator;
import com.siemens.pki.lightweightcmpra.protection.SignatureBasedProtection;

/**
 * downstream interface for nested message processing
 *
 */
public class DownstreamNestingFunction implements DownstreamNestingFunctionIF {

    private static final String INTERFACE_NAME = "nested downstream";
    private static final Logger LOGGER =
            LoggerFactory.getLogger(DownstreamNestingFunction.class);
    private final Function<PKIMessage, PKIMessage> wrappedDownstream;
    private final SignatureBasedProtection protectionProvider;
    private final InputValidator inputValidator;

    private final GeneralName expectedRecipient;

    /**
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     *
     * @param wrappedDownstream
     *            downstream handler for unwrapped messages
     * @throws Exception
     *             in case of error
     */
    DownstreamNestingFunction(final NESTEDENDPOINTCONFIGURATION config,
            final Function<PKIMessage, PKIMessage> wrappedDownstream)
            throws Exception {
        this.wrappedDownstream = wrappedDownstream;
        this.protectionProvider = new SignatureBasedProtection(config.getOut());
        this.inputValidator = new InputValidator(INTERFACE_NAME, config.getIn(),
                PKIBody.TYPE_NESTED);
        this.expectedRecipient =
                new GeneralName(new X500Name(config.getRecipient()));
    }

    @Override
    public PKIMessage apply(final PKIMessage msg) {
        try {
            inputValidator.validate(msg);
            final GeneralName receivedRecipient =
                    msg.getHeader().getRecipient();
            if (!expectedRecipient.equals(receivedRecipient)) {
                throw new CmpValidationException(INTERFACE_NAME,
                        PKIFailureInfo.badMessageCheck,
                        "expectedRecipient mismatch: " + expectedRecipient
                                + " <> " + receivedRecipient);
            }
            final PKIMessage[] nestedRequests =
                    ((PKIMessages) msg.getBody().getContent())
                            .toPKIMessageArray();
            final PKIMessage[] nestedResponses =
                    new PKIMessage[nestedRequests.length];
            for (int i = 0; i < nestedRequests.length; i++) {
                try {
                    try {
                        nestedResponses[i] =
                                wrappedDownstream.apply(nestedRequests[i]);
                    } catch (final BaseCmpException ex) {
                        nestedResponses[i] =
                                PkiMessageGenerator.generateAndProtectMessage(
                                        PkiMessageGenerator
                                                .buildRespondingHeaderProvider(
                                                        nestedRequests[i]),
                                        protectionProvider, ex.asErrorBody());
                    }
                } catch (final Exception ex) {
                    nestedResponses[i] =
                            PkiMessageGenerator.generateAndProtectMessage(
                                    PkiMessageGenerator
                                            .buildRespondingHeaderProvider(
                                                    nestedRequests[i]),
                                    protectionProvider,
                                    PkiMessageGenerator.generateErrorBody(
                                            PKIFailureInfo.systemFailure,
                                            "internal error: " + ex
                                                    .getLocalizedMessage()));
                }
            }
            return PkiMessageGenerator.generateAndProtectMessage(
                    PkiMessageGenerator.buildRespondingHeaderProvider(msg),
                    protectionProvider, new PKIBody(PKIBody.TYPE_NESTED,
                            new PKIMessages(nestedResponses)));
        } catch (final Exception e) {
            LOGGER.error("internal error", e);
            return null;
        }
    }
}
