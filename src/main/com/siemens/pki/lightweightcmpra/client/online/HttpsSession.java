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
package com.siemens.pki.lightweightcmpra.client.online;

import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.JAXB;

import com.siemens.pki.lightweightcmpra.config.xmlparser.HTTPCLIENTCONFIGURATION.TlsConfig;
import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.cryptoservices.TrustCredentialAdapter;
import com.siemens.pki.lightweightcmpra.msgvalidation.BaseCmpException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;

/**
 * Implementation of a CMP over HTTPS/TLS client.
 */
public class HttpsSession extends ClientSession {

    private final URL remoteUrl;

    // https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext
    //
    // SSL Supports some version of SSL; may support other versions
    // SSLv2 Supports SSL version 2 or later; may support other versions
    // SSLv3 Supports SSL version 3; may support other versions
    // TLS Supports some version of TLS; may support other versions
    // TLSv1 Supports RFC 2246: TLS version 1.0 ; may support other versions
    // TLSv1.1 Supports RFC 4346: TLS version 1.1 ; may support other versions
    // TLSv1.2 Supports RFC 5246: TLS version 1.2 ; may support other versions
    private final SSLContext sslContext = SSLContext.getInstance("TLSv1.2");

    /**
     * Constructor for the TLS Session handling.
     *
     * @param remoteUrl
     *            servers HTTP URL to connect to
     * @param tlsConfig
     *            {@link JAXB} TLS configuration subtree
     * @throws Exception
     *             in case of error
     */
    HttpsSession(final URL remoteUrl, final TlsConfig tlsConfig)
            throws Exception {
        final char[] keyStorePassword =
                tlsConfig.getKeyStorePassword().toCharArray();
        final KeyStore keyStore = CertUtility.loadKeystoreFromFile(
                tlsConfig.getKeyStorePath(), keyStorePassword);
        this.remoteUrl = remoteUrl;
        final KeyManagerFactory kmf = KeyManagerFactory
                .getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyStorePassword);
        final TrustManagerFactory tmf = TrustCredentialAdapter
                .createTrustManagerFactoryFromConfig(tlsConfig, true);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(),
                new SecureRandom());
    }

    /**
     * send a CMP message to the connected server and return response
     *
     * @param message
     *            the message to send
     *
     * @return responded message or <code>null</code> if something went wrong
     */
    @Override
    public InputStream apply(final byte[] message) {
        try {
            final HttpsURLConnection httpsConnection =
                    (HttpsURLConnection) remoteUrl.openConnection();
            httpsConnection.setSSLSocketFactory(sslContext.getSocketFactory());
            return sendReceivePkiMessageIntern(message, httpsConnection);
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Exception ex) {
            throw new CmpProcessingException(ex);
        }
    }
}
