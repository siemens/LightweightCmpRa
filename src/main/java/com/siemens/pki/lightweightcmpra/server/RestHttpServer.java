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
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.xml.bind.JAXB;

import com.siemens.pki.lightweightcmpra.config.xmlparser.HTTPSERVERCONFIGURATION;
import com.siemens.pki.lightweightcmpra.config.xmlparser.TLSSERVERCREDENTIALS;
import com.siemens.pki.lightweightcmpra.msgprocessing.RestServiceImplementation;
import com.sun.net.httpserver.HttpExchange;

/**
 *
 * a HTTP/HTTPS server needed for REST interfaces
 *
 */
@SuppressWarnings("restriction")
public class RestHttpServer extends BaseHttpServer {

    /**
     * create a HTTP/HTTPS server out of the given config
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @param restServiceImplementation
     *            the rest service to use
     *
     * @return a HTTP/HTTPS server created from the given config
     * @throws Exception
     *             in case of error
     */
    static public RestHttpServer createRestHttpServerFromConfig(
            final HTTPSERVERCONFIGURATION config,
            final RestServiceImplementation restServiceImplementation)
            throws Exception {
        final URL servingUrl = new URL(config.getServingUrl());
        switch (servingUrl.getProtocol().toLowerCase()) {
        case "http":
            return new RestHttpServer(servingUrl, restServiceImplementation);
        case "https": {
            final TLSSERVERCREDENTIALS tlsConfig = config.getTlsConfig();
            if (tlsConfig == null) {
                throw new IllegalArgumentException(
                        "https server without TlsConfig in configuration");
            }
            return new RestHttpServer(servingUrl, tlsConfig,
                    restServiceImplementation);
        }
        default:
            throw new IllegalArgumentException(
                    "invalid protocol for serving url given in configuration: "
                            + servingUrl.getProtocol());
        }
    }

    private static Map<String, String> parseQuery(final URI uri)
            throws UnsupportedEncodingException {
        final Map<String, String> query_pairs = new LinkedHashMap<>();
        for (final String pair : uri.getQuery().split("&")) {
            final int splitpos = pair.indexOf("=");
            final String key = splitpos > 0
                    ? URLDecoder.decode(pair.substring(0, splitpos), "UTF-8")
                    : pair;
            final String value = splitpos > 0 && pair.length() > splitpos + 1
                    ? URLDecoder.decode(pair.substring(splitpos + 1), "UTF-8")
                    : null;
            query_pairs.put(key, value);
        }
        return query_pairs;
    }

    private final RestServiceImplementation restServiceImplementation;

    private RestHttpServer(final URL servingUrl,
            final RestServiceImplementation restServiceImplementation)
            throws IOException {
        super(servingUrl);
        this.restServiceImplementation = restServiceImplementation;
    }

    private RestHttpServer(final URL servingUrl,
            final TLSSERVERCREDENTIALS tlsConfig,
            final RestServiceImplementation restServiceImplementation)
            throws Exception {
        super(servingUrl, tlsConfig);
        this.restServiceImplementation = restServiceImplementation;
    }

    @Override
    public void handle(final HttpExchange exchange) throws IOException {
        try {
            final String method = exchange.getRequestMethod().toUpperCase();
            switch (method) {
            case "DELETE":
                handleDelete(exchange);
                break;
            default:
                sendHttpResponse(exchange, HttpURLConnection.HTTP_BAD_METHOD,
                        "method " + method + " not supported");
            }
        } finally {
            exchange.getResponseBody().close();
        }

    }

    private void handleDelete(final HttpExchange exchange) {
        try {
            final Map<String, String> queryParams =
                    parseQuery(exchange.getRequestURI());
            final String issuer = queryParams.get("issuer");
            if (issuer == null) {
                sendHttpResponse(exchange, HttpURLConnection.HTTP_BAD_REQUEST,
                        "issuer missing in query");
                return;
            }
            final String serial = queryParams.get("serial");
            if (serial == null) {
                sendHttpResponse(exchange, HttpURLConnection.HTTP_BAD_REQUEST,
                        "serial missing in query");
                return;
            }
            if (!restServiceImplementation.doRevocation(issuer, serial)) {
                sendHttpResponse(exchange,
                        HttpURLConnection.HTTP_NOT_ACCEPTABLE,
                        "certificate not revoked");
                return;
            }
            sendHttpResponse(exchange, HttpURLConnection.HTTP_OK,
                    "certificate revoked");
        } catch (final Exception ex) {
            try {
                sendHttpResponse(exchange,
                        HttpURLConnection.HTTP_INTERNAL_ERROR,
                        "internal error: " + ex.getLocalizedMessage());
            } catch (final IOException e1) {
            }
        }
    }

    private void sendHttpResponse(final HttpExchange exchange,
            final int httpStatusCode, final String errorText)
            throws IOException {
        final byte[] responseBody = errorText.getBytes();
        exchange.getResponseHeaders().set("Content-Type", "text/plain");
        exchange.sendResponseHeaders(httpStatusCode, responseBody.length);
        exchange.getResponseBody().write(responseBody);

    }

}
