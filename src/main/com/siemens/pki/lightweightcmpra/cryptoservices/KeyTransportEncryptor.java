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

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

/**
 * encryptor which uses the key agreement key management technique for
 * encryption
 *
 */
public class KeyTransportEncryptor extends CmsEncryptorBase {
    /**
     *
     * @param encryptionCerts
     *            the public key certificate for the targeted recipients.
     */
    public KeyTransportEncryptor(
            final Collection<X509Certificate> encryptionCerts)
            throws GeneralSecurityException {

        final JcaX509ExtensionUtils jcaX509ExtensionUtils =
                new JcaX509ExtensionUtils();
        for (final X509Certificate encryptionCert : encryptionCerts) {
            final PublicKey publicKey = encryptionCert.getPublicKey();
            envGen.addRecipientInfoGenerator(
                    new JceKeyTransRecipientInfoGenerator(
                            jcaX509ExtensionUtils
                                    .createSubjectKeyIdentifier(publicKey)
                                    .getKeyIdentifier(),
                            publicKey).setProvider(
                                    CertUtility.BOUNCY_CASTLE_PROVIDER));
        }
    }

    /**
     * @param pathOfCertificateFile
     *            path to file holding the recipients certificates
     * @throws Exception
     */
    public KeyTransportEncryptor(final String pathOfCertificateFile)
            throws Exception {
        this(CertUtility.loadCertificatesFromFile(pathOfCertificateFile));
    }

    /**
     *
     * @param encryptionCerts
     *            the public key certificate for the targeted recipients.
     * @throws GeneralSecurityException
     */
    public KeyTransportEncryptor(final X509Certificate... encryptionCerts)
            throws GeneralSecurityException {
        this(Arrays.asList(encryptionCerts));
    }

}
