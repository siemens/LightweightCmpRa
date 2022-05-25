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

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;

/**
 * encryptor which uses the key agreement key management technique for
 * encryption
 *
 */
public class KeyAgreementEncryptor extends CmsEncryptorBase {

    public static final ASN1ObjectIdentifier DEFAULT_KEY_AGREEMENT =
            CMSAlgorithm.ECCDH_SHA256KDF;

    public static final ASN1ObjectIdentifier DEFAULT_KEY_ENCRYPTION =
            CMSAlgorithm.AES256_WRAP;

    private static ASN1ObjectIdentifier keyEncryptionOID =
            DEFAULT_KEY_ENCRYPTION;

    private static ASN1ObjectIdentifier keyAgreementOID = DEFAULT_KEY_AGREEMENT;

    /**
     * set key agreement algorithm, initial value is ECCDH_SHA256KDF
     *
     * @param keyAgreementOID
     *            key agreement algorithm
     */
    public static void setKeyAgreementOID(
            final ASN1ObjectIdentifier keyAgreementOID) {
        KeyAgreementEncryptor.keyAgreementOID = keyAgreementOID;
    }

    /**
     * set key encryption algorithm, initial value is AES256_WRAP
     *
     * @param keyEncryptionOID
     *            key encryption algorithm
     */
    public static void setKeyEncryptionOID(
            final ASN1ObjectIdentifier keyEncryptionOID) {
        KeyAgreementEncryptor.keyEncryptionOID = keyEncryptionOID;
    }

    /**
     *
     * @param keystore
     *            keystore to fetch the the private key and the certificate of
     *            the originator
     *
     * @param recipientCerts
     *            the public key certificate for the targeted recipients.
     *
     * @throws GeneralSecurityException
     *             if the necessary data cannot be extracted from the
     *             certificates
     */
    public KeyAgreementEncryptor(final BaseCredentialService keystore,
            final Collection<X509Certificate> recipientCerts)
            throws GeneralSecurityException {
        final JceKeyAgreeRecipientInfoGenerator infGen =
                new JceKeyAgreeRecipientInfoGenerator(keyAgreementOID,
                        keystore.getPrivateKey(),
                        keystore.getEndCertificate().getPublicKey(),
                        keyEncryptionOID);
        for (final X509Certificate aktCert : recipientCerts) {
            infGen.addRecipient(aktCert);
        }
        addRecipientInfoGenerator(
                infGen.setProvider(CertUtility.BOUNCY_CASTLE_PROVIDER));
    }

    /**
     *
     *
     * @param keystore
     *            keystore to fetch the the private key and the certificate of
     *            the originator
     *
     * @param recipientCerts
     *            the public key certificate for the targeted recipients.
     * @throws GeneralSecurityException
     *             if the necessary data cannot be extracted from the
     *             certificates
     */
    public KeyAgreementEncryptor(final BaseCredentialService keystore,
            final X509Certificate... recipientCerts)
            throws GeneralSecurityException {
        this(keystore, Arrays.asList(recipientCerts));
    }

    /**
     *
     * @param keystorePath
     *            path to keystore holding originators certificate and private
     *            key
     * @param keystorePassword
     *            password to open the keystore
     * @param pathOfCertificateFile
     *            path to file holding the recipients certificates
     * @throws Exception
     *             in case of general error while loading certificates
     */
    public KeyAgreementEncryptor(final String keystorePath,
            final String keystorePassword, final String pathOfCertificateFile)
            throws Exception {
        this(new BaseCredentialService(keystorePath,
                keystorePassword.toCharArray()),
                CertUtility.loadCertificatesFromFile(pathOfCertificateFile));
    }
}
