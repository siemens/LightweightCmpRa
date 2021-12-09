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
package com.siemens.pki.lightweightcmpra.protection;

import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;

import com.siemens.pki.lightweightcmpra.config.xmlparser.MACCREDENTIAL;
import com.siemens.pki.lightweightcmpra.cryptoservices.WrappedMac;
import com.siemens.pki.lightweightcmpra.cryptoservices.WrappedMacFactory;
import com.siemens.pki.lightweightcmpra.msgprocessing.NewCMPObjectIdentifiers;
import com.siemens.pki.lightweightcmpra.msgprocessing.PBMAC1Params;

/**
 * a {@link ProtectionProvider} enforcing a CMP message with PBMAC1
 * protection
 */
public class PBMAC1Protection extends MacProtection {

    public static final AlgorithmIdentifier DEFAULT_PRF =
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256,
                    DERNull.INSTANCE);

    public static final AlgorithmIdentifier DEFAULT_MAC = DEFAULT_PRF;

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

    /**
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     *
     * @throws Exception
     *             in the case of an internal error
     */
    public PBMAC1Protection(final MACCREDENTIAL config) throws Exception {
        this(config.getUsername(), config.getPassword(), 16,
                DEFAULT_ITERATION_COUNT, 256, DEFAULT_PRF, DEFAULT_MAC);
    }

    /**
     *
     * @param userName
     *            senderKID to use, can be null
     * @param password
     *            shared secret to protect with
     * @param saltLength
     *            length of salt
     * @param iterationCount
     *            number of iterations in key deviation
     * @param keyLength
     *            length of deviated key
     * @param prf
     *            PRF function used for key deviation
     * @param messageAuthScheme
     *            MAC function
     * @throws Exception
     *             in case of error
     */
    public PBMAC1Protection(final String userName, final String password,
            final int saltLength, final int iterationCount, final int keyLength,
            final AlgorithmIdentifier prf,
            final AlgorithmIdentifier messageAuthScheme) throws Exception {
        super(userName, password);
        final byte[] salt = createNewSalt(saltLength);
        final AlgorithmIdentifier keyDerivationFunc =
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2,
                        new PBKDF2Params(salt, iterationCount, keyLength, prf));
        final SecretKeyFactory keyFact =
                HELPER.createSecretKeyFactory(PBKDF2_ALG_NAMES.get(prf));
        final SecretKey key =
                keyFact.generateSecret(new PBEKeySpec(passwordAsCharArrays,
                        salt, iterationCount, keyLength));
        final AlgorithmIdentifier protectionAlg =
                new AlgorithmIdentifier(NewCMPObjectIdentifiers.pbmac1,
                        new PBMAC1Params(keyDerivationFunc, messageAuthScheme));
        final WrappedMac wrappedMac = WrappedMacFactory
                .createWrappedMac(messageAuthScheme, key.getEncoded());
        init(protectionAlg, wrappedMac);
    }
}
