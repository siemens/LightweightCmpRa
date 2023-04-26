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
package com.siemens.pki.lightweightcmpra.downstream.online;

import com.siemens.pki.lightweightcmpra.configuration.HttpsServerConfig;
import com.siemens.pki.lightweightcmpra.util.SslContextFactory;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URL;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * base HTTP/HTTPS server implementation
 *
 */
public abstract class BaseHttpServer implements HttpHandler {

    protected static final ExecutorService THREAD_POOL = Executors.newCachedThreadPool();
    private static final Logger LOGGER = LoggerFactory.getLogger(BaseHttpServer.class);

    protected final HttpServer httpServer;

    /**
     *
     * @param servingUrl
     *            URL to server
     * @throws IOException
     *             in case of error
     */
    protected BaseHttpServer(final URL servingUrl) throws IOException {
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("create HTTP server for " + servingUrl);
        }
        final int servingPort = servingUrl.getPort();
        final int port = servingPort > 0 ? servingPort : servingUrl.getDefaultPort();
        httpServer = HttpServer.create(new InetSocketAddress(port), 1);
        httpServer.createContext(servingUrl.getPath(), this);
        httpServer.setExecutor(THREAD_POOL);
        httpServer.start();
    }

    protected BaseHttpServer(final URL servingUrl, final HttpsServerConfig config) throws Exception {
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("create HTTPS server for " + servingUrl);
        }

        final SSLContext sslContext = SslContextFactory.createSslContext(
                config.getServerTrust(),
                config.getServerCredentials().getKeyStore(),
                config.getServerCredentials().getPassword());

        final HttpsServer httpsServer = HttpsServer.create(
                new InetSocketAddress(servingUrl.getPort() > 0 ? servingUrl.getPort() : servingUrl.getDefaultPort()),
                1);
        final boolean clientAuthenticationNeeded = config.isClientAuthenticationNeeded();

        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(final HttpsParameters params) {
                final SSLContext c = getSSLContext();
                final SSLParameters sslparams = c.getDefaultSSLParameters();
                sslparams.setNeedClientAuth(clientAuthenticationNeeded);
                final SSLEngine engine = c.createSSLEngine();
                params.setCipherSuites(engine.getEnabledCipherSuites());
                params.setProtocols(engine.getEnabledProtocols());
                params.setSSLParameters(sslparams);
            }
        });
        httpServer = httpsServer;
        httpServer.createContext(servingUrl.getPath(), this);
        httpServer.setExecutor(THREAD_POOL);
        httpServer.start();
    }

    /**
     * stop the server
     */
    public void stop() {
        httpServer.stop(1);
    }
}
