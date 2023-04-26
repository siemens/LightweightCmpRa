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

import java.io.IOException;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;

/**
 *
 * base class for CMS data encryption
 *
 */
public class CmsEncryptorBase {

    private final CMSEnvelopedDataGenerator envGen = new CMSEnvelopedDataGenerator();

    protected CmsEncryptorBase() {}

    protected void addRecipientInfoGenerator(final RecipientInfoGenerator recipientGenerator) {
        envGen.addRecipientInfoGenerator(recipientGenerator);
    }

    /**
     * encrypt the data
     *
     * @param msg
     *            data to encrypt
     * @return encrypted data
     *
     * @throws CMSException
     *             in case of an CMS processing error
     */
    public EnvelopedData encrypt(final byte[] msg) throws CMSException {
        final CMSEnvelopedData cmsEnvData = envGen.generate(
                new CMSProcessableByteArray(msg),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                        .setProvider(CertUtility.BOUNCY_CASTLE_PROVIDER)
                        .build());
        return EnvelopedData.getInstance(cmsEnvData.toASN1Structure().getContent());
    }

    /**
     * encrypt the data
     *
     * @param data
     *            signed data to encrypt
     * @return encrypted data
     * @throws CMSException
     *             in case of an CMS processing error
     * @throws IOException
     *             in case of ASN.1 encoding error
     */
    public EnvelopedData encrypt(final SignedData data) throws CMSException, IOException {
        final CMSEnvelopedData cmsEnvData = envGen.generate(
                new CMSProcessableByteArray(data.getEncoded()),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                        .setProvider(CertUtility.BOUNCY_CASTLE_PROVIDER)
                        .build());
        return EnvelopedData.getInstance(cmsEnvData.toASN1Structure().getContent());
    }
}
