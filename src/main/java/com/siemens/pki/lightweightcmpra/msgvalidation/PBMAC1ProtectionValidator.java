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
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;

import com.siemens.pki.lightweightcmpra.config.xmlparser.MACCREDENTIAL;
import com.siemens.pki.lightweightcmpra.cryptoservices.WrappedMac;
import com.siemens.pki.lightweightcmpra.cryptoservices.WrappedMacFactory;
import com.siemens.pki.lightweightcmpra.msgprocessing.PBMAC1Params;

/**
 * This class validates the PBMAC1 password based protection of
 * all incoming messages and generates proper error responses on
 * failed validation.
 */
public class PBMAC1ProtectionValidator extends MacValidator {

    private static final Map<AlgorithmIdentifier, String> PBKDF2_ALG_NAMES =
            new HashMap<AlgorithmIdentifier, String>();

    static {

        PBKDF2_ALG_NAMES.put(PasswordRecipient.PRF.HMacSHA1.getAlgorithmID(),
                "PBKDF2WITHHMACSHA1");
        PBKDF2_ALG_NAMES.put(PasswordRecipient.PRF.HMacSHA224.getAlgorithmID(),
                "PBKDF2WITHHMACSHA224");
        PBKDF2_ALG_NAMES.put(PasswordRecipient.PRF.HMacSHA256.getAlgorithmID(),
                "PBKDF2WITHHMACSHA256");
        PBKDF2_ALG_NAMES.put(PasswordRecipient.PRF.HMacSHA384.getAlgorithmID(),
                "PBKDF2WITHHMACSHA384");
        PBKDF2_ALG_NAMES.put(PasswordRecipient.PRF.HMacSHA512.getAlgorithmID(),
                "PBKDF2WITHHMACSHA512");
    }

    private static final DefaultJcaJceHelper HELPER = new DefaultJcaJceHelper();

    private final char[] passwordAsCharArray;

    public PBMAC1ProtectionValidator(final String interfaceName,
            final MACCREDENTIAL config) {
        super(interfaceName, config.getUsername());
        passwordAsCharArray = config.getPassword().toCharArray();
    }

    @Override
    public void validate(final PKIMessage message)
            throws CmpProcessingException {
        super.validate(message);
        try {
            final PKIHeader header = message.getHeader();
            final PBMAC1Params pbmac1Params = PBMAC1Params
                    .getInstance(header.getProtectionAlg().getParameters());
            final AlgorithmIdentifier keyDerivationFunc =
                    pbmac1Params.getKeyDerivationFunc();
            if (!PKCSObjectIdentifiers.id_PBKDF2
                    .equals(keyDerivationFunc.getAlgorithm())) {
                throw new CmpValidationException(getInterfaceName(),
                        PKIFailureInfo.badMessageCheck,
                        "PBKDF2 protection check failed, unsupported keyDerivationFunc");
            }
            final PBKDF2Params params =
                    PBKDF2Params.getInstance(keyDerivationFunc.getParameters());
            final SecretKeyFactory keyFact = HELPER.createSecretKeyFactory(
                    PBKDF2_ALG_NAMES.get(params.getPrf()));

            final SecretKey key = keyFact.generateSecret(
                    new PBEKeySpec(passwordAsCharArray, params.getSalt(),
                            params.getIterationCount().intValue(),
                            params.getKeyLength().intValue()));
            final WrappedMac mac = WrappedMacFactory.createWrappedMac(
                    pbmac1Params.getMessageAuthScheme(), key.getEncoded());
            final byte[] protectedBytes =
                    new ProtectedPart(header, message.getBody())
                            .getEncoded(ASN1Encoding.DER);
            final byte[] recalculatedProtection =
                    mac.calculateMac(protectedBytes);
            final byte[] protectionBytes = message.getProtection().getBytes();
            if (!Arrays.equals(recalculatedProtection, protectionBytes)) {
                throw new CmpValidationException(getInterfaceName(),
                        PKIFailureInfo.badMessageCheck,
                        "PasswordBasedMac protection check failed");
            }
        } catch (final BaseCmpException cex) {
            throw cex;
        } catch (final Exception ex) {
            throw new CmpProcessingException(getInterfaceName(),
                    PKIFailureInfo.badMessageCheck, ex.getLocalizedMessage());

        }
    }

}
