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
package com.siemens.pki.lightweightcmpra.test.framework;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.cms.PasswordRecipient.PRF;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;

/**
 * encryptor which uses the the MAC protected key management technique for
 * encryption
 *
 */
public class PasswordEncryptor extends CmsEncryptorBase {

    public static final ASN1ObjectIdentifier DEFAULT_KEK_ALG =
            CMSAlgorithm.AES256_CBC;

    public static final PRF DEFAULT_PRF = PasswordRecipient.PRF.HMacSHA256;

    private static PRF prf = DEFAULT_PRF;

    private static ASN1ObjectIdentifier kekAlgorithmOID = DEFAULT_KEK_ALG;

    public static final int DEFAULT_ITERATIONCOUNT = 10_000;

    private static int iterationCount = DEFAULT_ITERATIONCOUNT;

    /**
     * set iterationCount for key deviation, initial value is 10000
     *
     * @param iterationCount
     *            iterationCount for key deviation
     */
    public static void setIterationCount(final int iterationCount) {
        PasswordEncryptor.iterationCount = iterationCount;
    }

    /**
     * set key encryption algorithm, initial value is AES256_CBC
     *
     * @param kekAlgorithmOID
     *            key encryption algorithm
     */
    public static void setKekAlgorithmOID(
            final ASN1ObjectIdentifier kekAlgorithmOID) {
        PasswordEncryptor.kekAlgorithmOID = kekAlgorithmOID;
    }

    /**
     * set pseudo random function for key deviation, initial value is HMacSHA256
     *
     * @param prf
     *            pseudo random function
     */
    public static void setPrf(final PRF prf) {
        PasswordEncryptor.prf = prf;
    }

    /**
     *
     * @param passwd
     *            the password to use as the basis of the PBE key.
     * @throws Exception
     *             in case of error
     */
    public PasswordEncryptor(final char[] passwd) throws Exception {
        addRecipientInfoGenerator(
                new JcePasswordRecipientInfoGenerator(kekAlgorithmOID, passwd)
                        .setProvider(CertUtility.BOUNCY_CASTLE_PROVIDER)
                        .setPasswordConversionScheme(
                                PasswordRecipient.PKCS5_SCHEME2_UTF8)
                        .setPRF(prf).setSaltAndIterationCount(
                                CertUtility.generateRandomBytes(20),
                                iterationCount));
    }

    /**
     *
     * @param passwd
     *            the password to use as the basis of the PBE key.
     * @throws Exception
     *             in case of error
     */
    public PasswordEncryptor(final String passwd) throws Exception {
        this(passwd.toCharArray());
    }
}
