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

import static com.siemens.pki.cmpracomponent.util.NullUtil.computeDefaultIfNull;

import java.net.URI;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Collections;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.cmpracomponent.configuration.CkgKeyAgreementContext;
import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.lightweightcmpra.util.CredentialLoader;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class CkgKeyAgreementContextImpl extends CkgContextImpl
        implements CkgKeyAgreementContext {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(CkgKeyAgreementContextImpl.class);

    private String KeyAgreementAlg;
    private String KeyEncryptionAlg;
    private URI keyStore;
    private PrivateKey OwnPrivateKey;

    private PublicKey OwnPublicKey;
    private byte[] password;

    @Override
    public String getKeyAgreementAlg() {
        return computeDefaultIfNull(KeyAgreementAlg,
                CkgKeyAgreementContext.super::getKeyAgreementAlg);
    }

    @Override
    public String getKeyEncryptionAlg() {
        return computeDefaultIfNull(KeyEncryptionAlg,
                CkgKeyAgreementContext.super::getKeyEncryptionAlg);
    }

    @Override
    public PrivateKey getOwnPrivateKey() {
        if (OwnPrivateKey == null) {
            extractKeysFromKeystore();
        }
        return OwnPrivateKey;
    }

    @Override
    public PublicKey getOwnPublicKey() {
        if (OwnPublicKey == null) {
            extractKeysFromKeystore();
        }
        return OwnPublicKey;
    }

    public byte[] getPassword() {
        return password;
    }

    @XmlElement(required = true)
    public void setKeyAgreementAlg(final String keyAgreementAlg) {
        KeyAgreementAlg = keyAgreementAlg;
    }

    public void setKeyEncryptionAlg(final String keyEncryptionAlg) {
        KeyEncryptionAlg = keyEncryptionAlg;
    }

    @XmlElement(required = true)
    public void setKeyStore(final URI keyStore) {
        this.keyStore = keyStore;
    }

    @XmlElement(required = true)
    public void setPassword(final byte[] password) {
        this.password = password;
    }

    private void extractKeysFromKeystore() {
        final char[] passwordAsChars =
                AlgorithmHelper.convertSharedSecretToPassword(password);
        final KeyStore ks =
                CredentialLoader.loadKeyStore(keyStore, passwordAsChars);
        if (ks == null) {
            return;
        }
        try {
            for (final String aktAlias : Collections.list(ks.aliases())) {
                try {
                    final Key key = ks.getKey(aktAlias, passwordAsChars);
                    final Certificate[] chain =
                            ks.getCertificateChain(aktAlias);
                    if (key instanceof PrivateKey && chain != null
                            && chain.length > 0) {
                        OwnPrivateKey = (PrivateKey) key;
                        OwnPublicKey = chain[0].getPublicKey();
                        return;
                    }
                } catch (UnrecoverableKeyException | KeyStoreException
                        | NoSuchAlgorithmException e) {
                    LOGGER.warn("could not extract keyStore from " + keyStore,
                            e);
                }
            }
        } catch (final KeyStoreException e) {
            LOGGER.error("could not extract keyStore from " + keyStore, e);
        }

    }
}
