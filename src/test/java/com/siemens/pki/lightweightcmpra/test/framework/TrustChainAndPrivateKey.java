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

import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

public class TrustChainAndPrivateKey {

    // chain starting with end certificate ending with root certificate
    private final ArrayList<X509Certificate> trustChain = new ArrayList<>();

    private PrivateKey privateKeyOfEndCertififcate = null;

    public TrustChainAndPrivateKey(final String keyStoreFileName, final char[] password) throws Exception {
        this(CertUtility.loadKeystoreFromFile(keyStoreFileName, password), password);
    }

    TrustChainAndPrivateKey(final KeyStore keyStore, final char[] password) throws Exception {
        for (final String aktAlias : Collections.list(keyStore.aliases())) {
            final Key privKey = keyStore.getKey(aktAlias, password);
            if (!(privKey instanceof PrivateKey)) {
                continue;
            }
            final Certificate certificate = keyStore.getCertificate(aktAlias);
            if (!(certificate instanceof X509Certificate)) {
                continue;
            }
            final Certificate[] foundChain = keyStore.getCertificateChain(aktAlias);
            for (final Certificate aktCert : foundChain) {
                trustChain.add((X509Certificate) aktCert);
            }
            privateKeyOfEndCertififcate = (PrivateKey) privKey;
            return;
        }
        throw new SecurityException("no chain in Keystore");
    }

    public PrivateKey getPrivateKeyOfEndCertififcate() {
        return privateKeyOfEndCertififcate;
    }

    public ProtectionProvider setEndEntityToProtect(final CMPCertificate certificate, final PrivateKey privateKey)
            throws Exception {
        final AlgorithmIdentifier protectionAlg = SignHelperUtil.getSigningAlgIdFromKey(privateKey);

        final GeneralName senderName = new GeneralName(
                X500Name.getInstance(certificate.getX509v3PKCert().getSubject().getEncoded(ASN1Encoding.DER)));
        final DEROctetString senderKid =
                CertUtility.extractSubjectKeyIdentifierFromCert(CertUtility.certificateFromCmpCertificate(certificate));
        return new ProtectionProvider() {
            @Override
            public List<CMPCertificate> getProtectingExtraCerts()
                    throws java.security.cert.CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
                final List<CMPCertificate> ret = new ArrayList<>(trustChain.size());
                ret.add(certificate);
                for (final X509Certificate aktCert : trustChain) {
                    if (CertUtility.isSelfSigned(aktCert)) {
                        // chain root reached
                        break;
                    }
                    ret.add(CertUtility.cmpCertificateFromCertificate(aktCert));
                }
                return ret;
            }

            @Override
            public AlgorithmIdentifier getProtectionAlg() {
                return protectionAlg;
            }

            @Override
            public DERBitString getProtectionFor(final ProtectedPart protectedPart)
                    throws GeneralSecurityException, IOException {
                final Signature sig = Signature.getInstance(SignHelperUtil.getSigningAlgNameFromKey(privateKey));
                sig.initSign(privateKey);
                sig.update(protectedPart.getEncoded(ASN1Encoding.DER));
                return new DERBitString(sig.sign());
            }

            @Override
            public GeneralName getSender() {
                return senderName;
            }

            @Override
            public DEROctetString getSenderKID() {
                return senderKid;
            }
        };
    }

    List<X509Certificate> getTrustChain() {
        return new ArrayList<>(trustChain);
    }
}
