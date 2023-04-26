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
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * a HTTP/HTTPS server needed for CMP downstream interfaces
 *
 */
public class CmpHttpServer extends BaseHttpServer implements DownstreamInterface {

    public static final Logger LOGGER = LoggerFactory.getLogger(CmpHttpServer.class);

    private final ExFunction messageHandler;

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
        super(servingUrl);
        this.messageHandler = messageHandler;
    }

    public CmpHttpServer(final URL servingUrl, final ExFunction messageHandler, final HttpsServerConfig config)
            throws Exception {
        super(servingUrl, config);

        this.messageHandler = messageHandler;
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
            final byte[] encodedResponse =
                    messageHandler.apply(exchange.getRequestBody().readAllBytes());
            if (encodedResponse == null) {
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_INTERNAL_ERROR, -1);
            } else {
                exchange.getResponseHeaders().set("Content-Type", "application/pkixcmp");
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, encodedResponse.length);
                exchange.getResponseBody().write(encodedResponse);
            }
        } catch (final Exception e) {
            LOGGER.error("error while processing request", e);
            final byte[] responseBody = ("error while processing request: " + e.getLocalizedMessage()).getBytes();
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_INTERNAL_ERROR, responseBody.length);
            exchange.getResponseBody().write(responseBody);
        } finally {
            exchange.getResponseBody().close();
        }
    }
}
