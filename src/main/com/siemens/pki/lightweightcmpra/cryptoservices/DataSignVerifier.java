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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.BiFunction;

import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;

import com.siemens.pki.lightweightcmpra.config.xmlparser.TRUSTCREDENTIALS;

/**
 * a verifier for CMS signed data
 *
 *
 */
public class DataSignVerifier extends TrustCredentialAdapter {

    private static JcaSimpleSignerInfoVerifierBuilder builder =
            new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(CertUtility.BOUNCY_CASTLE_PROVIDER);

    public static byte[] verifySignature(final byte[] encodedSignedData)
            throws CMSException, Exception, IOException {
        return verifySignature(encodedSignedData,
                (cert, additionalCerts) -> true);
    }

    private static byte[] verifySignature(final byte[] encodedSignedData,
            final BiFunction<X509CertificateHolder, List<X509Certificate>, Boolean> trustValidator)
            throws CMSException, Exception, IOException {

        final CMSSignedData signedData = new CMSSignedData(
                new ContentInfo(CMSObjectIdentifiers.signedData,
                        SignedData.getInstance(encodedSignedData)));
        final SignerInformationStore signers = signedData.getSignerInfos();
        final Store<X509CertificateHolder> certs = signedData.getCertificates();
        final List<X509Certificate> allCerts = new ArrayList<X509Certificate>();
        for (final X509CertificateHolder aktCert : certs.getMatches(null)) {
            allCerts.add(
                    CertUtility.certificateFromEncoded(aktCert.getEncoded()));
        }
        for (final SignerInformation signerInfo : signers) {
            @SuppressWarnings("unchecked")
            final Collection<X509CertificateHolder> certCollection =
                    certs.getMatches(signerInfo.getSID());
            final X509CertificateHolder cert = certCollection.iterator().next();
            try {
                if (signerInfo.verify(builder.build(cert))
                        && trustValidator.apply(cert, allCerts)) {
                    final CMSTypedData cmsData = signedData.getSignedContent();
                    final ByteArrayOutputStream bOut =
                            new ByteArrayOutputStream();
                    cmsData.write(bOut);
                    return bOut.toByteArray();
                }
            } catch (final Exception e) {
                // try next signer
            }
        }
        return null;
    }

    public DataSignVerifier(final TRUSTCREDENTIALS config)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, Exception {
        super(config);
    }

    private boolean validate(final X509CertificateHolder cert,
            final List<X509Certificate> allCerts) throws Exception {
        return validateCertAgainstTrust(
                CertUtility.certificateFromEncoded(cert.getEncoded()),
                allCerts) != null;
    }

    /**
     * Verify the passed in encoding of a CMS SignedData, assumes encapsulated
     * data.
     *
     * @param encodedSignedData
     *            the BER encoding of the SignedData
     * @return signed content or null if not trusted
     * @throws Exception
     */
    public byte[] verifySignatureAndTrust(final byte[] encodedSignedData)
            throws Exception {
        return verifySignature(encodedSignedData,
                (cert, additionalIntermediateCerts) -> {
                    try {
                        return validate(cert, additionalIntermediateCerts);
                    } catch (final Exception e) {
                        return false;
                    }
                });
    }

    public PrivateKey verifySignedKey(final byte[] encodedSignedData)
            throws Exception {
        final byte[] verifiedContent =
                verifySignatureAndTrust(encodedSignedData);
        if (verifiedContent == null) {
            return null;
        }
        final PKCS8EncodedKeySpec pkcs8EncKeySpec =
                new PKCS8EncodedKeySpec(verifiedContent);
        PrivateKey prvKey;
        try {
            prvKey = KeyFactory.getInstance("RSA")
                    .generatePrivate(pkcs8EncKeySpec);
        } catch (final InvalidKeySpecException excpt) {
            prvKey = KeyFactory.getInstance("EC")
                    .generatePrivate(pkcs8EncKeySpec);
        }
        return prvKey;
    }

}
