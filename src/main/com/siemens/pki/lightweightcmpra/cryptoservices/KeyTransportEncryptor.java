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
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Collection;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;

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
        final JcaAlgorithmParametersConverter paramsConverter =
                new JcaAlgorithmParametersConverter();

        final AlgorithmIdentifier oaepParams = paramsConverter
                .getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP,
                        new OAEPParameterSpec("SHA-256", "MGF1",
                                new MGF1ParameterSpec("SHA-256"),
                                PSource.PSpecified.DEFAULT));

        for (final X509Certificate encryptionCert : encryptionCerts) {
            envGen.addRecipientInfoGenerator(
                    new JceKeyTransRecipientInfoGenerator(encryptionCert,
                            oaepParams).setProvider(
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
