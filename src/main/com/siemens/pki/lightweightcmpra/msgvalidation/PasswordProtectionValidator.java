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

import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.config.xmlparser.MACCREDENTIAL;
import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

/**
 * This class validates the signature or password based
 * protection of all incoming messages and generates proper error responses on
 * failed validation.
 */
public class PasswordProtectionValidator implements ValidatorIF {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(PasswordProtectionValidator.class);

    private final String interfaceName;

    private final DEROctetString pbeUsernameForProtectionValidation;

    private final byte[] pbeSecretForProtectionValidation;

    public PasswordProtectionValidator(final String interfaceName,
            final MACCREDENTIAL config) {
        this.interfaceName = interfaceName;
        pbeSecretForProtectionValidation = config.getPassword().getBytes();
        final String username = config.getUsername();
        if (username != null) {
            pbeUsernameForProtectionValidation =
                    new DEROctetString(username.getBytes());
        } else {
            pbeUsernameForProtectionValidation = null;
        }
    }

    @Override
    public void validate(final PKIMessage message)
            throws CmpProcessingException {
        try {
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
                            LOGGER.warn(
                                    "wrong username returned in recipKID of "
                                            + MessageDumper.msgTypeAsString(
                                                    message)
                                            + ", ignored");
                        }
                    } else {
                        LOGGER.warn("no username returned in "
                                + MessageDumper.msgTypeAsString(message)
                                + ", ignored");
                    }
                }
            }
            final byte[] protectionSecret = pbeSecretForProtectionValidation;
            // Construct the base key according to rfc4210, section 5.1.3.1
            final PBMParameter pmbParameter = PBMParameter
                    .getInstance(header.getProtectionAlg().getParameters());
            final byte[] salt = pmbParameter.getSalt().getOctets();
            byte[] basekey = new byte[protectionSecret.length + salt.length];
            System.arraycopy(protectionSecret, 0, basekey, 0,
                    protectionSecret.length);
            System.arraycopy(salt, 0, basekey, protectionSecret.length,
                    salt.length);
            final MessageDigest dig = MessageDigest.getInstance(
                    pmbParameter.getOwf().getAlgorithm().getId(),
                    CertUtility.BOUNCY_CASTLE_PROVIDER);
            final int iterationCount =
                    pmbParameter.getIterationCount().getValue().intValue();
            for (int i = 0; i < iterationCount; i++) {
                basekey = dig.digest(basekey);
                dig.reset();
            }
            final String macId = pmbParameter.getMac().getAlgorithm().getId();
            final Mac mac =
                    Mac.getInstance(macId, CertUtility.BOUNCY_CASTLE_PROVIDER);
            mac.init(new SecretKeySpec(basekey, macId));
            final byte[] protectedBytes =
                    new ProtectedPart(header, message.getBody())
                            .getEncoded(ASN1Encoding.DER);
            mac.update(protectedBytes);
            final byte[] recalculatedProtection = mac.doFinal();
            final byte[] protectionBytes = message.getProtection().getBytes();
            if (!Arrays.equals(recalculatedProtection, protectionBytes)) {
                throw new CmpValidationException(interfaceName,
                        PKIFailureInfo.badMessageCheck,
                        "PasswordBasedMac protection check failed ");
            }
        } catch (final BaseCmpException cex) {
            throw cex;
        } catch (final Exception ex) {
            throw new CmpProcessingException(interfaceName,
                    PKIFailureInfo.badMessageCheck, ex.getLocalizedMessage());

        }
    }
}
