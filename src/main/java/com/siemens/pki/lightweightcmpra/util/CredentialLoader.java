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
package com.siemens.pki.lightweightcmpra.util;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;

/**
 * utility class to load various credentials, certificates and CRLs from URIs
 *
 */
public class CredentialLoader {
    protected static CertificateFactory cf = null;

    private static final Logger LOGGER =
            LoggerFactory.getLogger(CredentialLoader.class);

    static {
        try {
            cf = CertificateFactory.getInstance("X.509",
                    CertUtility.getBouncyCastleProvider());
        } catch (final CertificateException e) {
            LOGGER.error("error creating CertificateFactory ", e);
        }
    }

    /**
     * load all certificates from all give URIs
     *
     * @param uris
     *            URIs to load from
     * @return loaded certificates
     */
    @SuppressWarnings("unchecked")
    public static List<X509Certificate> loadCertificates(final URI... uris) {
        if (uris == null || uris.length == 0 || uris[0] == null) {
            return Collections.emptyList();
        }
        final ArrayList<X509Certificate> ret = new ArrayList<>(uris.length);
        for (final URI aktUri : uris) {
            try (InputStream is = new BufferedInputStream(
                    ConfigFileLoader.getConfigUriAsStream(aktUri))) {
                while (is.available() > 0) {
                    ret.addAll((Collection<? extends X509Certificate>) cf
                            .generateCertificates(is));
                }

            } catch (final IOException | CertificateException e) {
                final String msg = "error loading Certificate from " + aktUri;
                LOGGER.error(msg, e);
                throw new RuntimeException(msg, e);
            }
        }
        return ret;
    }

    /**
     * load all CRLs from all give URIs
     *
     * @param uris
     *            URIs to load from
     * @return loaded CRLs
     */
    public static List<X509CRL> loadCRLs(final URI... uris) {
        if (uris == null || uris.length == 0 || uris[0] == null) {
            return Collections.emptyList();
        }
        final ArrayList<X509CRL> ret = new ArrayList<>(uris.length);
        for (final URI aktUri : uris) {
            try (InputStream is = new BufferedInputStream(
                    ConfigFileLoader.getConfigUriAsStream(aktUri))) {
                while (is.available() > 0) {
                    ret.add((X509CRL) cf.generateCRL(is));
                }

            } catch (final IOException | CRLException e) {
                final String message = "error loading CRL from " + aktUri;
                LOGGER.error(message, e);
                throw new RuntimeException(message, e);
            }
        }
        return ret;
    }

    public static KeyStore loadKeyStore(final URI uri, final char[] password) {
        if (uri == null) {
            return null;
        }
        try (InputStream is = new BufferedInputStream(
                ConfigFileLoader.getConfigUriAsStream(uri))) {
            is.mark(is.available());
            GeneralSecurityException lastException = null;
            for (final String keyStoreType : new String[] {"PKCS12", "JKS",
                    "BKS"}) {
                try {
                    final KeyStore ks = KeyStore.getInstance(keyStoreType);
                    ks.load(is, password);
                    return ks;
                } catch (NoSuchAlgorithmException | CertificateException
                        | KeyStoreException e) {
                    lastException = e;
                    is.reset();
                }
            }
            final String msg = "error loading KeyStore from " + uri;
            LOGGER.error(msg, lastException);
            throw new RuntimeException(msg, lastException);
        } catch (final IOException e) {
            final String msg = "error loading KeyStore from " + uri;
            LOGGER.error(msg, e);
            throw new RuntimeException(msg, e);
        }
    }

    // utility class
    private CredentialLoader() {

    }

}
