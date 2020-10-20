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
package com.siemens.pki.lightweightcmpra.server;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.function.Function;

import javax.xml.bind.JAXB;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.config.xmlparser.HTTPSERVERCONFIGURATION;
import com.siemens.pki.lightweightcmpra.config.xmlparser.TLSSERVERCREDENTIALS;
import com.sun.net.httpserver.HttpExchange;

/**
 *
 * a HTTP/HTTPS server needed for CMP downstream interfaces
 *
 */
@SuppressWarnings("restriction")
public class CmpHttpServer extends BaseHttpServer {

    public static final Logger LOGGER =
            LoggerFactory.getLogger(CmpHttpServer.class);

    /**
     * create a HTTP/HTTPS server out of the given config
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @param messageHandler
     *            related upstream interface
     * @return a HTTP/HTTPS server created from the given config
     * @throws Exception
     *             in case of error
     */
    static public CmpHttpServer createCmpHttpServerFromConfig(
            final HTTPSERVERCONFIGURATION config,
            final Function<InputStream, byte[]> messageHandler)
            throws Exception {
        final URL servingUrl = new URL(config.getServingUrl());
        switch (servingUrl.getProtocol().toLowerCase()) {
        case "http":
            return new CmpHttpServer(servingUrl, messageHandler);
        case "https": {
            final TLSSERVERCREDENTIALS tlsConfig = config.getTlsConfig();
            if (tlsConfig == null) {
                throw new IllegalArgumentException(
                        "https server without TlsConfig in configuration");
            }
            return new CmpHttpServer(servingUrl, messageHandler, tlsConfig);
        }
        default:
            throw new IllegalArgumentException(
                    "invalid protocol for serving url given in configuration: "
                            + servingUrl.getProtocol());
        }
    }

    private final Function<InputStream, byte[]> messageHandler;

    /**
     *
     * @param servingUrl
     *            URL to server
     * @param messageHandler
     *            related downstream handler
     * @throws IOException
     *             in case of error
     */
    public CmpHttpServer(final URL servingUrl,
            final Function<InputStream, byte[]> messageHandler)
            throws IOException {
        super(servingUrl);
        this.messageHandler = messageHandler;
    }

    private CmpHttpServer(final URL servingUrl,
            final Function<InputStream, byte[]> messageHandler,
            final TLSSERVERCREDENTIALS tlsConfig) throws Exception {
        super(servingUrl, tlsConfig);

        this.messageHandler = messageHandler;
    }

    @Override
    public synchronized void handle(final HttpExchange exchange)
            throws IOException {
        try {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                final byte[] responseBody =
                        "only HTTP POST is supported".getBytes();
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_BAD_METHOD,
                        responseBody.length);
                exchange.getResponseBody().write(responseBody);
                return;
            }
            final byte[] encodedResponse =
                    messageHandler.apply(exchange.getRequestBody());
            if (encodedResponse == null) {
                exchange.sendResponseHeaders(
                        HttpURLConnection.HTTP_INTERNAL_ERROR, -1);
            } else {
                exchange.getResponseHeaders().set("Content-Type",
                        "application/pkixcmp");
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK,
                        encodedResponse.length);
                exchange.getResponseBody().write(encodedResponse);
            }
        } catch (final Exception e) {
            LOGGER.error("error while processing request", e);
            final byte[] responseBody = ("error while processing request: "
                    + e.getLocalizedMessage()).getBytes();
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_INTERNAL_ERROR,
                    responseBody.length);
            exchange.getResponseBody().write(responseBody);
        } finally {
            exchange.getResponseBody().close();
        }
    }
}
