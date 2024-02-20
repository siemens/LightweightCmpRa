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
import com.siemens.pki.lightweightcmpra.downstream.DownstreamInterface;
import com.siemens.pki.lightweightcmpra.util.SslContextFactory;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.HttpURLConnection;
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
 * a HTTP/HTTPS server needed for CMP downstream interfaces
 *
 */
public class CmpHttpServer implements HttpHandler, DownstreamInterface {

    private static final Logger LOGGER = LoggerFactory.getLogger(CmpHttpServer.class);

    private static final ExecutorService THREAD_POOL = Executors.newCachedThreadPool();

    private final ExFunction messageHandler;

    protected final HttpServer httpServer;

    /**
     *
     * @param servingUrl
     *            URL to server
     * @param messageHandler
     *            related downstream handler
     * @throws IOException
     *             in case of error
     */
    public CmpHttpServer(final URL servingUrl, final DownstreamInterface.ExFunction messageHandler) throws IOException {
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("create HTTP server for " + servingUrl);
        }
        this.messageHandler = messageHandler;
        final int servingPort = servingUrl.getPort();
        final int port = servingPort > 0 ? servingPort : servingUrl.getDefaultPort();
        httpServer = HttpServer.create(new InetSocketAddress(port), 1);
        startHttpServer(servingUrl);
    }

    public CmpHttpServer(final URL servingUrl, final ExFunction messageHandler, final HttpsServerConfig config)
            throws Exception {
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("create HTTPS server for " + servingUrl);
        }

        this.messageHandler = messageHandler;

        final SSLContext sslContext = SslContextFactory.createSslContext(
                config.getServerTrust(),
                config.getServerCredentials().getKeyStore(),
                config.getServerCredentials().getPassword());

        final HttpsServer httpsServer = HttpsServer.create(
                new InetSocketAddress(servingUrl.getPort() > 0 ? servingUrl.getPort() : servingUrl.getDefaultPort()),
                1);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(final HttpsParameters params) {
                final SSLContext c = getSSLContext();
                final SSLParameters sslparams = c.getDefaultSSLParameters();
                sslparams.setNeedClientAuth(config.isClientAuthenticationNeeded());
                final SSLEngine engine = c.createSSLEngine();
                params.setCipherSuites(engine.getEnabledCipherSuites());
                params.setProtocols(engine.getEnabledProtocols());
                params.setSSLParameters(sslparams);
            }
        });
        httpServer = httpsServer;
        startHttpServer(servingUrl);
    }

    @Override
    public synchronized void handle(final HttpExchange exchange) throws IOException {
        try {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                final byte[] responseBody = "only HTTP POST is supported".getBytes();
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_BAD_METHOD, responseBody.length);
                exchange.getResponseBody().write(responseBody);
                return;
            }
            final byte[] rawRequest = exchange.getRequestBody().readAllBytes();
            if (rawRequest == null || rawRequest.length < 1) {
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_NO_CONTENT, -1);
                return;
            }
            final byte[] encodedResponse = messageHandler.apply(rawRequest);
            if (encodedResponse == null) {
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_BAD_REQUEST, -1);
            } else {
                exchange.getResponseHeaders().set("Content-Type", "application/pkixcmp");
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, encodedResponse.length);
                exchange.getResponseBody().write(encodedResponse);
            }
        } catch (final Exception e) {
            final int statusCode =
                    e.getCause() != null ? HttpURLConnection.HTTP_BAD_REQUEST : HttpURLConnection.HTTP_INTERNAL_ERROR;
            LOGGER.error("error while processing request", e);
            final byte[] responseBody = ("error while processing request: " + e.getLocalizedMessage()).getBytes();
            exchange.sendResponseHeaders(statusCode, responseBody.length);
            exchange.getResponseBody().write(responseBody);
        } finally {
            exchange.getResponseBody().close();
        }
    }

    private void startHttpServer(final URL servingUrl) {
        httpServer.createContext(servingUrl.getPath(), this);
        httpServer.setExecutor(THREAD_POOL);
        httpServer.start();
    }

    /**
     * stop the server
     */
    @Override
    public void stop() {
        httpServer.stop(1);
    }
}
