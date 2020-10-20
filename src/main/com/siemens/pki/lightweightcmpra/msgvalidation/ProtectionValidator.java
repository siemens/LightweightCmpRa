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

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.config.xmlparser.CMPCREDENTIALS;
import com.siemens.pki.lightweightcmpra.config.xmlparser.CMPCREDENTIALS.In.SignatureBased;
import com.siemens.pki.lightweightcmpra.config.xmlparser.MACCREDENTIAL;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

/**
 * This class validates the signature or password based
 * protection of all incoming messages and generates proper error responses on
 * failed validation.
 */
public class ProtectionValidator implements ValidatorIF {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(ProtectionValidator.class);

    private final boolean enforceIncomingProtection;

    private final String interfaceName;

    private PasswordProtectionValidator passwordProtectionValidator;

    private SignatureProtectionValidator signatureProtectionValidator;

    /**
     *
     * @param interfaceName
     *            interface name used in error messages
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @throws Exception
     *             in case of error
     */
    public ProtectionValidator(final String interfaceName,
            final CMPCREDENTIALS.In config) throws Exception {
        this.interfaceName = interfaceName;
        enforceIncomingProtection = config.isEnforceProtection();
        final MACCREDENTIAL passwordBased = config.getPasswordBased();
        if (passwordBased != null) {
            passwordProtectionValidator = new PasswordProtectionValidator(
                    interfaceName, passwordBased);
        } else {
            passwordProtectionValidator = null;
        }
        final SignatureBased signatureBased = config.getSignatureBased();
        if (signatureBased != null) {
            signatureProtectionValidator = new SignatureProtectionValidator(
                    interfaceName, signatureBased);
        } else {
            signatureProtectionValidator = null;
        }
    }

    /**
     * Check a incoming message for correct protection
     *
     * @param message
     *            message to check
     * @throws CmpProcessingException
     *             in case of error or failed protection validation
     *
     */
    @Override
    public void validate(final PKIMessage message)
            throws CmpProcessingException {
        final DERBitString protection = message.getProtection();
        final AlgorithmIdentifier protectionAlg =
                message.getHeader().getProtectionAlg();
        if (protectionAlg != null) {
            if (protection == null || protection.getBytes().length == 0) {
                throw new CmpValidationException(interfaceName,
                        PKIFailureInfo.wrongIntegrity,
                        "protectionAlg given but protection missing");
            }
            if (CMPObjectIdentifiers.passwordBasedMac
                    .equals(protectionAlg.getAlgorithm())) {
                if (passwordProtectionValidator == null) {
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.wrongIntegrity,
                            "message is protected by PasswordBasedMac but no shared secret is known");
                }
                passwordProtectionValidator.validate(message);
            } else {
                if (signatureProtectionValidator == null) {
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.signerNotTrusted,
                            "signature-based protection was not configured here");
                }
                signatureProtectionValidator.validate(message);
            }
        } else {
            if (protection != null && protection.getBytes().length > 0) {
                throw new CmpValidationException(interfaceName,
                        PKIFailureInfo.wrongIntegrity,
                        "protectionAlg missing but protection given");
            }
            if ((passwordProtectionValidator != null
                    || signatureProtectionValidator != null)
                    && enforceIncomingProtection) {
                switch (message.getBody().getType()) {
                case PKIBody.TYPE_ERROR:
                case PKIBody.TYPE_CONFIRM:
                case PKIBody.TYPE_REVOCATION_REP:
                    // some messages are allowed to be unprotected or protected
                    // in an
                    // strange way
                    LOGGER.warn("broken protection ignored for "
                            + MessageDumper.msgTypeAsString(message.getBody()));
                    return;
                default:
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.badMessageCheck,
                            "a protection is required but not provided");
                }
            }
        }
    }

}
