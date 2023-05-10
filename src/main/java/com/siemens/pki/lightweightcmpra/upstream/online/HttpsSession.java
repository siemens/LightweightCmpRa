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
package com.siemens.pki.lightweightcmpra.upstream.online;

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import com.siemens.pki.lightweightcmpra.configuration.HttpsClientConfig;
import com.siemens.pki.lightweightcmpra.configuration.SignatureCredentialContextImpl;
import com.siemens.pki.lightweightcmpra.util.SslContextFactory;
import java.net.URL;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of a CMP over HTTPS/TLS client.
 */
public class HttpsSession extends HttpSession {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpsSession.class);

    private final SSLContext sslContext;

    private boolean disableHostnameVerification;

    /**
     * Constructor for the TLS Session handling.
     *
     * @param remoteUrl        servers HTTPS URL to connect to
     * @param timeoutInSeconds connection and read timeout
     * @param config           TLS configuration
     *
     * @throws Exception in case of error
     */
    public HttpsSession(final URL remoteUrl, final int timeoutInSeconds, final HttpsClientConfig config)
            throws Exception {
        super(remoteUrl, timeoutInSeconds);
        final SignatureCredentialContextImpl clientCredentials = config.getClientCredentials();
        disableHostnameVerification = config.isDisableHostnameVerification();
        sslContext = SslContextFactory.createSslContext(
                config.getClientTrust(),
                ifNotNull(clientCredentials, SignatureCredentialContextImpl::getKeyStore),
                ifNotNull(clientCredentials, SignatureCredentialContextImpl::getPassword));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] apply(final byte[] message, final String certProfile) {
        try {
            final HttpsURLConnection httpsConnection = (HttpsURLConnection) remoteUrl.openConnection();
            httpsConnection.setSSLSocketFactory(sslContext.getSocketFactory());
            if (disableHostnameVerification) {
                httpsConnection.setHostnameVerifier(new HostnameVerifier() {

                    @Override
                    public boolean verify(String hostname, SSLSession session) {
                        return true;
                    }
                });
            }
            return sendReceivePkiMessageIntern(message, httpsConnection, timeoutInSeconds);
        } catch (final Exception ex) {
            LOGGER.warn("client connection to " + remoteUrl, ex);
            throw new RuntimeException("client connection to " + remoteUrl, ex);
        }
    }
}
