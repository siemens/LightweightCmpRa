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

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.CollectionStore;

/**
 *
 * a signer to produce CMS SignedData
 *
 */
public class DataSigner {

    private final ASN1ObjectIdentifier id_ct_KP_aKeyPackage =
            new ASN1ObjectIdentifier("1.2.16.840.1.101.2.1.2.78.5");

    private final CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

    public DataSigner(final BaseCredentialService credentialService)
            throws OperatorCreationException, CertificateEncodingException,
            IOException, CMSException {
        final SignerInfoGenerator signerInfoGenerator =
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setProvider(CertUtility.BOUNCY_CASTLE_PROVIDER)
                        .build(credentialService.getSignatureAlgorithmName(),
                                credentialService.getPrivateKey(),
                                credentialService.getEndCertificate());
        gen.addSignerInfoGenerator(signerInfoGenerator);

        final List<X509CertificateHolder> certChain =
                new ArrayList<X509CertificateHolder>();
        for (final X509Certificate aktCert : credentialService.getCertChain()) {
            certChain.add(new X509CertificateHolder(aktCert.getEncoded()));
        }
        gen.addCertificates(
                new CollectionStore<X509CertificateHolder>(certChain));
    }

    public DataSigner(final PrivateKey privateKey,
            final X509Certificate endCertificate) throws Exception {
        this(new BaseCredentialService(privateKey, endCertificate,
                Arrays.asList(endCertificate)));
    }

    /**
     * @param keyStorePath
     *            path to load the signing keystore
     * @param password
     *            password to open the signing keystore
     */
    public DataSigner(final String keyStorePath, final char[] password)
            throws Exception {
        this(new BaseCredentialService(keyStorePath, password));
    }

    /**
     * @param keyStorePath
     *            path to load the signing keystore
     * @param password
     *            password to open the signing keystore
     * @throws Exception
     *             in case of error
     */
    public DataSigner(final String keyStorePath, final String password)
            throws Exception {
        this(keyStorePath, password.toCharArray());
    }

    /**
     * Create a SignedData structure
     *
     * @param msg
     *            the raw message data to encapsulate and sign
     *
     * @return the SignedData.
     * @throws CMSException
     *             in case of error
     */
    public SignedData signData(final byte[] msg) throws CMSException {
        final CMSSignedData cmsSigned = gen.generate(
                new CMSProcessableByteArray(id_ct_KP_aKeyPackage, msg), true);
        final ContentInfo contentInfo = cmsSigned.toASN1Structure();
        return SignedData.getInstance(contentInfo.getContent());
    }

    /**
     * Create a SignedData structure
     *
     * @param privateKey
     *            a private key to encapsulate and sign
     *
     * @return the SignedData
     * @throws CMSException
     *             in case of error
     * @throws IOException
     */
    public SignedData signPrivateKey(final PrivateKey privateKey)
            throws CMSException, IOException {
        return signData(PrivateKeyInfo.getInstance(privateKey.getEncoded())
                .getEncoded(ASN1Encoding.DER));
    }
}
