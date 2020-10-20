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
package com.siemens.pki.lightweightcmpra.cryptoservices;

import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;

/**
 * encryptor which uses the the MAC protected key management technique for
 * encryption
 *
 */
public class PasswordEncryptor extends CmsEncryptorBase {
    private static final int ITERATIONCOUNT = 567;

    /**
     *
     * @param passwd
     *            the password to use as the basis of the PBE key.
     * @throws Exception
     *             in case of error
     */
    public PasswordEncryptor(final char[] passwd) throws Exception {
        envGen.addRecipientInfoGenerator(
                new JcePasswordRecipientInfoGenerator(CMSAlgorithm.AES256_CBC,
                        passwd).setProvider(CertUtility.BOUNCY_CASTLE_PROVIDER)
                                .setPasswordConversionScheme(
                                        PasswordRecipient.PKCS5_SCHEME2_UTF8)
                                .setPRF(PasswordRecipient.PRF.HMacSHA256)
                                .setSaltAndIterationCount(
                                        CertUtility.generateRandomBytes(20),
                                        ITERATIONCOUNT));
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
