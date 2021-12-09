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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;

import com.siemens.pki.lightweightcmpra.config.xmlparser.CMPCREDENTIALS;
import com.siemens.pki.lightweightcmpra.config.xmlparser.TRUSTCREDENTIALS;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

/**
 * validator for an incoming message
 *
 */
public class InputValidator implements ValidatorIF {

    private final ValidatorIF protectionValidator;
    private final Set<Integer> supportedMessageTypes;
    private final ValidatorIF messageValidator;
    private final String interfaceName;

    /**
     *
     * @param interfaceName
     *            name of the attached interface used for logging
     * @param acceptRaVerify
     *            should raVerified accepted for POPO?
     * @param config
     *            {@link JAXB} configuration subtree for CMP protection
     * @param supportedMessageTypes
     *            acceptable CMP message types
     * @throws Exception
     *             in case of general error
     */
    public InputValidator(final String interfaceName,
            final boolean acceptRaVerify, final CMPCREDENTIALS.In config,
            final Integer... supportedMessageTypes) throws Exception {
        this.interfaceName = interfaceName;
        protectionValidator = new ProtectionValidator(interfaceName, config);
        this.messageValidator =
                new MessageValidator(interfaceName, acceptRaVerify,
                        config.getAllowedTimeDeviationInSeconds().intValue());
        this.supportedMessageTypes =
                new HashSet<>(Arrays.asList(supportedMessageTypes));
    }

    public InputValidator(final String interfaceName,
            final TRUSTCREDENTIALS config,
            final Integer... supportedMessageTypes) throws Exception {
        this.interfaceName = interfaceName;
        protectionValidator =
                new SignatureProtectionValidator(interfaceName, config);
        this.messageValidator = new MessageValidator(interfaceName, true, 600);
        this.supportedMessageTypes =
                new HashSet<>(Arrays.asList(supportedMessageTypes));
    }

    /**
     * validate a message according to the given configuration and acceptable
     * message types
     *
     * @param in
     *            message to validate
     * @throws CmpProcessingException
     *             if validation failed
     */
    @Override
    public void validate(final PKIMessage in) throws CmpProcessingException {

        protectionValidator.validate(in);
        messageValidator.validate(in);
        if (!supportedMessageTypes.contains(in.getBody().getType())) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badMessageCheck,
                    "message " + MessageDumper.msgTypeAsString(in)
                            + " not supported ");
        }
    }
}
