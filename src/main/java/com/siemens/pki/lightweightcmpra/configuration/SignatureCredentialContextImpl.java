/*
 *  Copyright (c) 2022 Siemens AG
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
package com.siemens.pki.lightweightcmpra.configuration;

import static com.siemens.pki.cmpracomponent.util.NullUtil.defaultIfNull;

import com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext;
import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.lightweightcmpra.util.CredentialLoader;
import java.net.URI;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class SignatureCredentialContextImpl extends CredentialContextImpl implements SignatureCredentialContext {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignatureCredentialContextImpl.class);

    private URI keyStore;
    private byte[] password;

    private String SignatureAlgorithmName;

    private transient List<X509Certificate> certificateChainAsList;

    private transient PrivateKey privateKeyAsPK;

    @Override
    public List<X509Certificate> getCertificateChain() {
        if (certificateChainAsList == null) {
            extractKeyAndChainFromKeyStore();
        }
        return certificateChainAsList;
    }

    public URI getKeyStore() {
        return keyStore;
    }

    public byte[] getPassword() {
        return password;
    }

    @Override
    public PrivateKey getPrivateKey() {
        if (privateKeyAsPK == null) {
            extractKeyAndChainFromKeyStore();
        }
        return privateKeyAsPK;
    }

    @Override
    public String getSignatureAlgorithmName() {
        return defaultIfNull(SignatureAlgorithmName, SignatureCredentialContext.super.getSignatureAlgorithmName());
    }

    @XmlElement(required = true)
    public void setKeyStore(final URI keyStore) {
        this.keyStore = keyStore;
    }

    @XmlElement(required = true)
    public void setPassword(final byte[] password) {
        this.password = password;
    }

    public void setSignatureAlgorithmName(final String signatureAlgorithmName) {
        SignatureAlgorithmName = signatureAlgorithmName;
    }

    private void extractKeyAndChainFromKeyStore() {
        final char[] passwordAsChars = AlgorithmHelper.convertSharedSecretToPassword(password);
        final KeyStore ks = CredentialLoader.loadKeyStore(keyStore, passwordAsChars);
        if (ks == null) {
            return;
        }
        final String msg = "could not extract keyStore from " + keyStore;
        try {
            for (final String aktAlias : Collections.list(ks.aliases())) {

                try {
                    final Key key = ks.getKey(aktAlias, passwordAsChars);
                    final Certificate[] chain = ks.getCertificateChain(aktAlias);
                    if (key instanceof PrivateKey && chain != null) {
                        privateKeyAsPK = (PrivateKey) key;
                        if (certificateChainAsList == null) {
                            certificateChainAsList = new ArrayList<>(chain.length);
                        }
                        for (final Certificate aktCert : chain) {
                            certificateChainAsList.add((X509Certificate) aktCert);
                        }
                        return;
                    }
                } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
                    LOGGER.warn(msg, e);
                }
            }
        } catch (final KeyStoreException e) {
            LOGGER.error(msg, e);
            throw new RuntimeException(msg, e);
        }
    }
}
