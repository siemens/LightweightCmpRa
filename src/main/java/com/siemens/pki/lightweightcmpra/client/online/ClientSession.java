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
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.function.Function;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.config.xmlparser.HTTPCLIENTCONFIGURATION;
import com.siemens.pki.lightweightcmpra.config.xmlparser.HTTPCLIENTCONFIGURATION.TlsConfig;
import com.siemens.pki.lightweightcmpra.msgprocessing.UpstreamNestingFunctionIF;
import com.siemens.pki.lightweightcmpra.util.MsgProcessingAdapter;

/**
 * Implementation of a generic CMP client.
 */
abstract public class ClientSession implements Function<byte[], InputStream> {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(ClientSession.class);

    /**
     * create a {@link ClientSession} from a given {@link JAXB} configuration
     * subtree
     *
     * @param config
     *            {@link JAXB} configuration from XML configuration file
     * @param nestingFunction
     *            wrapper/un-wrapper for nested messages
     * @return a new created {@link ClientSession}
     * @throws Exception
     *             in case of error
     */
    static public Function<PKIMessage, PKIMessage> createClientSessionFromConfig(
            final HTTPCLIENTCONFIGURATION config,
            final UpstreamNestingFunctionIF nestingFunction) throws Exception {
        final URL serverUrl = new URL(config.getServerUrl());
        ClientSession session;
        switch (serverUrl.getProtocol().toLowerCase()) {
        case "http":
            session = new HttpSession(serverUrl);
            break;
        case "https": {
            final TlsConfig tlsConfig = config.getTlsConfig();
            if (tlsConfig == null) {
                throw new IllegalArgumentException(
                        "https client without TlsConfig in configuration");
            }
            session = new HttpsSession(serverUrl, tlsConfig);
            break;
        }
        default:
            throw new IllegalArgumentException(
                    "invalid protocol for serving url given in configuration: "
                            + serverUrl.getProtocol());
        }
        return nestingFunction.getAsWrappingFunction(
                MsgProcessingAdapter.adaptByteToInputStreamFunctionToMsgHandler(
                        "HTTP_client", session));

    }

    protected ClientSession() {
    }

    /**
     * send a CMP message to the connected server and return response
     *
     * @param message
     *            the message to send
     *
     * @return responded message or <code>null</code> if something went wrong
     *
     */
    @Override
    abstract public InputStream apply(final byte[] message);

    /**
     * send a CMP message to the already connected server and return received
     * CMP
     * message
     *
     * @param message
     *            the message to send
     * @param httpConnection
     *            used HTTP(S) connection
     *
     * @return responded message or <code>null</code> if something went wrong
     *
     * @throws Exception
     *             if something went wrong in message encoding or CMP message
     *             transfer
     */
    protected InputStream sendReceivePkiMessageIntern(final byte[] message,
            final HttpURLConnection httpConnection) throws Exception {
        httpConnection.setDoInput(true);
        httpConnection.setDoOutput(true);
        httpConnection.setConnectTimeout(30000);
        httpConnection.setReadTimeout(30000);
        httpConnection.setRequestMethod("POST");
        httpConnection.setRequestProperty("Content-type",
                "application/pkixcmp");
        httpConnection.connect();
        try (final OutputStream outputStream =
                httpConnection.getOutputStream()) {
            outputStream.write(message);
        }
        final int lastResponseCode = httpConnection.getResponseCode();

        if (lastResponseCode == HttpURLConnection.HTTP_OK) {
            return httpConnection.getInputStream();
        }
        LOGGER.error("got response '" + httpConnection.getResponseMessage()
                + "(" + lastResponseCode + ")' from " + httpConnection
                + ", closing client");
        return null;
    }
}
