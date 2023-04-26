/*
 *  Copyright (c) 2023 Siemens AG
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

import com.siemens.pki.lightweightcmpra.upstream.UpstreamInterface;
import java.io.IOException;
import java.net.URI;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.elements.exception.ConnectorException;

/**
 * Implementation of a CMP over CoAP client.
 */
public class CmpCoapClient implements UpstreamInterface {

    private final CoapClient client;

    public CmpCoapClient(URI uri, int timeout) {
        client = new CoapClient(uri);
        if (timeout <= 0) {
            timeout = Integer.MAX_VALUE / 2;
        }
        client.setTimeout(timeout * 1000L);
    }

    @Override
    public byte[] apply(final byte[] message, final String certProfile) {
        try {
            return client.post(message, MediaTypeRegistry.APPLICATION_OCTET_STREAM)
                    .getPayload();
        } catch (ConnectorException | IOException e) {
            throw new RuntimeException("client connection to " + client.getURI(), e);
        }
    }

    @Override
    public void setDelayedResponseHandler(final AsyncResponseHandler asyncResponseHandler) {
        // no async response expected
    }
}
