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

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.upstream.UpstreamInterface;

/**
 * Implementation of a HTTP client.
 */
public class HttpSession implements UpstreamInterface {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(HttpSession.class);

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
    protected static byte[] sendReceivePkiMessageIntern(final byte[] message,
            final HttpURLConnection httpConnection, final int timeoutInSeconds)
            throws Exception {
        httpConnection.setDoInput(true);
        httpConnection.setDoOutput(true);
        httpConnection.setConnectTimeout(timeoutInSeconds * 1000);
        httpConnection.setReadTimeout(timeoutInSeconds * 1000);
        httpConnection.setRequestMethod("POST");
        httpConnection.setRequestProperty("Content-type",
                "application/pkixcmp");
        httpConnection.connect();
        try (final OutputStream outputStream =
                httpConnection.getOutputStream()) {
            LOGGER.debug(
                    "send " + message.length + " bytes to " + httpConnection);
            outputStream.write(message);
        }
        final int lastResponseCode = httpConnection.getResponseCode();

        if (lastResponseCode == HttpURLConnection.HTTP_OK) {
            final byte[] response =
                    httpConnection.getInputStream().readAllBytes();
            LOGGER.debug(
                    "got " + response.length + " bytes from " + httpConnection);
            return response;
        }
        final String errorString =
                "got response '" + httpConnection.getResponseMessage() + "("
                        + lastResponseCode + ")' from " + httpConnection;
        LOGGER.error(errorString + ", closing client");
        throw new Exception(errorString);
    }

    protected final URL remoteUrl;
    protected final int timeoutInSeconds;

    /**
     *
     * @param remoteUrl
     *            servers HTTP URL to connect to
     * @param timeoutInSeconds
     *            connection and read timeout
     * @throws Exception
     *             in case of error
     */
    public HttpSession(final URL remoteUrl, final int timeoutInSeconds)
            throws Exception {
        this.remoteUrl = remoteUrl;
        this.timeoutInSeconds = timeoutInSeconds;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] apply(final byte[] message, final String certProfile) {
        try {
            final HttpURLConnection httpConnection =
                    (HttpURLConnection) remoteUrl.openConnection();
            return sendReceivePkiMessageIntern(message, httpConnection,
                    timeoutInSeconds);
        } catch (final Exception e) {
            throw new RuntimeException("client connection to " + remoteUrl, e);
        }
    }

    @Override
    public void setDelayedResponseHandler(
            final AsyncResponseHandler asyncResponseHandler) {
        // no async response expected
    }
}
