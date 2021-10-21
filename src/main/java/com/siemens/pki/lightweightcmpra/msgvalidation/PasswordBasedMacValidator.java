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

import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import com.siemens.pki.lightweightcmpra.config.xmlparser.MACCREDENTIAL;
import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;

/**
 * This class validates the password based protection as define in RFC4210 of
 * all incoming messages and generates proper error responses on
 * failed validation.
 */
public class PasswordBasedMacValidator extends MacValidator {

    private final byte[] passwordAsBytes;

    public PasswordBasedMacValidator(final String interfaceName,
            final MACCREDENTIAL config) {
        super(interfaceName, config.getUsername());
        passwordAsBytes = config.getPassword().getBytes();
    }

    @Override
    public void validate(final PKIMessage message)
            throws CmpProcessingException {
        super.validate(message);
        try {
            final PKIHeader header = message.getHeader();
            // Construct the base key according to rfc4210, section 5.1.3.1
            final PBMParameter pbmParameter = PBMParameter
                    .getInstance(header.getProtectionAlg().getParameters());
            final byte[] salt = pbmParameter.getSalt().getOctets();
            final int iterationCount =
                    pbmParameter.getIterationCount().getValue().intValue();
            final AlgorithmIdentifier owf = pbmParameter.getOwf();
            byte[] basekey = new byte[passwordAsBytes.length + salt.length];
            System.arraycopy(passwordAsBytes, 0, basekey, 0,
                    passwordAsBytes.length);
            System.arraycopy(salt, 0, basekey, passwordAsBytes.length,
                    salt.length);
            final MessageDigest dig =
                    MessageDigest.getInstance(owf.getAlgorithm().getId(),
                            CertUtility.BOUNCY_CASTLE_PROVIDER);
            for (int i = 0; i < iterationCount; i++) {
                basekey = dig.digest(basekey);
                dig.reset();
            }
            final String macId = pbmParameter.getMac().getAlgorithm().getId();
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
                throw new CmpValidationException(getInterfaceName(),
                        PKIFailureInfo.badMessageCheck,
                        "PasswordBasedMac protection check failed ");
            }
        } catch (final BaseCmpException cex) {
            throw cex;
        } catch (final Exception ex) {
            throw new CmpProcessingException(getInterfaceName(),
                    PKIFailureInfo.badMessageCheck, ex.getLocalizedMessage());

        }
    }

}
