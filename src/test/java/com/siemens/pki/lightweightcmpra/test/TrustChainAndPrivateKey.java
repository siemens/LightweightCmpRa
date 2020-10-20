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
package com.siemens.pki.lightweightcmpra.test;

import java.security.Key;
import java.security.KeyStore;
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
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.cryptoservices.CmsEncryptorBase;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;

class TrustChainAndPrivateKey {

    // chain starting with end certificate ending with root certificate
    private final ArrayList<X509Certificate> trustChain = new ArrayList<>();

    private PrivateKey privateKeyOfEndCertififcate = null;

    TrustChainAndPrivateKey(final KeyStore keyStore, final char[] password)
            throws Exception {
        for (final String aktAlias : Collections.list(keyStore.aliases())) {
            final Key privKey = keyStore.getKey(aktAlias, password);
            if (!(privKey instanceof PrivateKey)) {
                continue;
            }
            final Certificate certificate = keyStore.getCertificate(aktAlias);
            if (!(certificate instanceof X509Certificate)) {
                continue;
            }
            final Certificate[] foundChain =
                    keyStore.getCertificateChain(aktAlias);
            for (final Certificate aktCert : foundChain) {
                trustChain.add((X509Certificate) aktCert);
            }
            privateKeyOfEndCertififcate = (PrivateKey) privKey;
            return;
        }
        throw new SecurityException("no chain in Keystore");
    }

    TrustChainAndPrivateKey(final String keyStoreFileName,
            final char[] password) throws Exception {
        this(CertUtility.loadKeystoreFromFile(keyStoreFileName, password),
                password);
    }

    public PrivateKey getPrivateKeyOfEndCertififcate() {
        return privateKeyOfEndCertififcate;
    }

    List<X509Certificate> getTrustChain() {
        return new ArrayList<>(trustChain);
    }

    ProtectionProvider setEndEntityToProtect(final CMPCertificate certificate,
            final PrivateKey privateKey) throws Exception {
        String algorithmName = privateKey.getAlgorithm();
        if ("EC".equalsIgnoreCase(algorithmName)) {
            algorithmName = "ECDSA";
        }
        AlgorithmIdentifier protectionAlg;
        if ("RSA".equalsIgnoreCase(algorithmName)) {
            protectionAlg = new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.sha256WithRSAEncryption);
        } else {
            protectionAlg = new AlgorithmIdentifier(
                    X9ObjectIdentifiers.ecdsa_with_SHA256);
        }
        final String signatureAlgorithmName = "SHA256with" + algorithmName;
        final GeneralName senderName = new GeneralName(X500Name.getInstance(
                certificate.getX509v3PKCert().getSubject().getEncoded()));
        final DEROctetString senderKid =
                CertUtility.extractSubjectKeyIdentifierFromCert(
                        CertUtility.certificateFromCmpCertificate(certificate));
        return new ProtectionProvider() {
            @Override
            public CmsEncryptorBase getKeyEncryptor(
                    final CMPCertificate endEntityCertificate) {
                throw new CmpProcessingException("downstream",
                        PKIFailureInfo.notAuthorized,
                        "private key encryption failed, no credentials available");
            }

            @Override
            public List<CMPCertificate> getProtectingExtraCerts()
                    throws Exception {
                final List<CMPCertificate> ret =
                        new ArrayList<>(trustChain.size());
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
            public DERBitString getProtectionFor(
                    final ProtectedPart protectedPart) throws Exception {
                final Signature sig =
                        Signature.getInstance(signatureAlgorithmName);
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

}