/*
 *  Copyright (c) 2021 Siemens AG
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

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.util.MessageDumper;

/**
 * base class for all MAC based validators
 *
 */
public class MacValidator implements ValidatorIF {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(MacValidator.class);

    private final String interfaceName;

    private final DEROctetString pbeUsernameForProtectionValidation;

    protected MacValidator(final String interfaceName, final String username) {
        this.interfaceName = interfaceName;
        if (username != null) {
            pbeUsernameForProtectionValidation =
                    new DEROctetString(username.getBytes());
        } else {
            pbeUsernameForProtectionValidation = null;
        }
    }

    protected String getInterfaceName() {
        return interfaceName;
    }

    @Override
    public void validate(final PKIMessage message) {
        final PKIHeader header = message.getHeader();
        if (pbeUsernameForProtectionValidation != null) {
            final ASN1OctetString senderKID = header.getSenderKID();
            if (senderKID != null) {
                if (!Arrays.equals(
                        pbeUsernameForProtectionValidation.getOctets(),
                        senderKID.getOctets())) {
                    LOGGER.warn("wrong username returned in senderKID of "
                            + MessageDumper.msgTypeAsString(message)
                            + ", ignored");
                }
            } else {
                final ASN1OctetString recipKID = header.getRecipKID();
                if (recipKID != null) {
                    if (!Arrays.equals(
                            pbeUsernameForProtectionValidation.getOctets(),
                            recipKID.getOctets())) {
                        LOGGER.warn("wrong username returned in recipKID of "
                                + MessageDumper.msgTypeAsString(message)
                                + ", ignored");
                    }
                } else {
                    LOGGER.warn("no username returned in "
                            + MessageDumper.msgTypeAsString(message)
                            + ", ignored");
                }
            }
        }
    }
}
