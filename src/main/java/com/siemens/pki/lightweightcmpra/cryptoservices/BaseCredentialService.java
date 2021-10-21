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

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/**
 * base class for certificate based signing and encryption services
 *
 */
public class BaseCredentialService {

    private final PrivateKey privateKey;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final String signatureAlgorithmName;
    private final X509Certificate endCertificate;
    private final List<X509Certificate> certChain = new ArrayList<>();

    public BaseCredentialService(final PrivateKey privateKey,
            final X509Certificate endCertificate,
            final Collection<X509Certificate> certChain) {
        this.privateKey = privateKey;
        this.endCertificate = endCertificate;
        this.certChain.addAll(certChain);
        String algorithmName = privateKey.getAlgorithm();
        if ("EC".equalsIgnoreCase(algorithmName)) {
            algorithmName = "ECDSA";
        }
        if ("RSA".equalsIgnoreCase(algorithmName)) {
            signatureAlgorithm = new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.sha256WithRSAEncryption);
        } else {
            signatureAlgorithm = new AlgorithmIdentifier(
                    X9ObjectIdentifiers.ecdsa_with_SHA256);
        }
        signatureAlgorithmName = "SHA256with" + algorithmName;
    }

    /**
     * @param keyStorePath
     *            path to load the serving keystore
     * @param password
     *            password to open the serving keystore
     */
    public BaseCredentialService(final String keyStorePath,
            final char[] password) throws Exception {
        final KeyStore keyStore =
                CertUtility.loadKeystoreFromFile(keyStorePath, password);

        final Map<String, X509Certificate> certsFromKeystore = new HashMap<>();
        PrivateKey lastFoundPrivateKey = null;
        X509Certificate lastFoundEndCertificate = null;
        for (final String aktAlias : Collections.list(keyStore.aliases())) {
            final Certificate[] certificateChain =
                    keyStore.getCertificateChain(aktAlias);
            if (certificateChain != null) {
                for (final Certificate aktChainCert : certificateChain) {
                    final X509Certificate x509aktChainCert =
                            (X509Certificate) aktChainCert;
                    if (CertUtility.isSelfSigned(x509aktChainCert)) {
                        // ignore all root certificates
                        continue;
                    }
                    certsFromKeystore.put(
                            x509aktChainCert.getSubjectDN().getName(),
                            x509aktChainCert);
                }
            }
            final Certificate certificate = keyStore.getCertificate(aktAlias);
            if (!(certificate instanceof X509Certificate)) {
                continue;
            }
            final X509Certificate x509Certificate =
                    (X509Certificate) certificate;
            if (CertUtility.isSelfSigned(x509Certificate)) {
                continue;
            }
            certsFromKeystore.put(x509Certificate.getSubjectDN().getName(),
                    x509Certificate);
            final Key aktKey = keyStore.getKey(aktAlias, password);
            if (!(aktKey instanceof PrivateKey)) {
                continue;
            }
            // found candidate for own certificate and private key
            lastFoundPrivateKey = (PrivateKey) aktKey;
            lastFoundEndCertificate = x509Certificate;
        }
        privateKey = lastFoundPrivateKey;
        endCertificate = lastFoundEndCertificate;
        if (privateKey == null || endCertificate == null) {
            throw new KeyStoreException(
                    "no keypair (certificate + private key) for protection found");
        }
        String algorithmName = privateKey.getAlgorithm();
        if ("EC".equalsIgnoreCase(algorithmName)) {
            algorithmName = "ECDSA";
        }
        if ("RSA".equalsIgnoreCase(algorithmName)) {
            signatureAlgorithm = new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.sha256WithRSAEncryption);
        } else {
            signatureAlgorithm = new AlgorithmIdentifier(
                    X9ObjectIdentifiers.ecdsa_with_SHA256);
        }
        signatureAlgorithmName = "SHA256with" + algorithmName;
        // bring the certificates in the correct order
        // poor mens chain building, never use this algorithm for chain validation!
        certChain.add(endCertificate);
        String curIssuer = endCertificate.getIssuerDN().getName();
        for (;;) {
            final X509Certificate nextIssuer =
                    certsFromKeystore.remove(curIssuer);
            if (nextIssuer == null) {
                break;
            }
            certChain.add(nextIssuer);
            curIssuer = nextIssuer.getIssuerDN().getName();
        }
    }

    protected List<X509Certificate> getCertChain() {
        return certChain;
    }

    public X509Certificate getEndCertificate() {
        return endCertificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    protected AlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    protected String getSignatureAlgorithmName() {
        return signatureAlgorithmName;
    }
}
