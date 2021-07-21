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
package com.siemens.pki.lightweightcmpra.test;

import java.io.IOException;
import java.net.URL;
import java.security.SecureRandom;
import java.util.function.Function;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.elements.exception.ConnectorException;

import com.siemens.pki.lightweightcmpra.client.online.HttpSession;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;
import com.siemens.pki.lightweightcmpra.util.MsgProcessingAdapter;

/**
 *
 *
 */
public class TestUtils {

    static final String PASSWORD = "Password";

    static final SecureRandom RANDOM = new SecureRandom();

    static final char[] PASSWORD_AS_CHAR_ARRAY = PASSWORD.toCharArray();

    /**
     * create a HTTP CMP client
     *
     * @param serverPath
     *            server URL to contact
     * @return
     * @throws Exception
     */
    public static Function<PKIMessage, PKIMessage> createCmpClient(
            final String serverPath) throws Exception {
        if (serverPath.toLowerCase().startsWith("http")) {
            return MsgProcessingAdapter
                    .adaptByteToInputStreamFunctionToMsgHandler(
                            "HTTP(S) test client",
                            new HttpSession(new URL(serverPath)));
        } else {
            if (serverPath.toLowerCase().startsWith("coap")) {
                final CoapClient client = new CoapClient(serverPath);
                return MsgProcessingAdapter.adaptByteToByteFunctionToMsgHandler(
                        "COAP test client", in -> {
                            try {
                                return client.post(in,
                                        MediaTypeRegistry.APPLICATION_OCTET_STREAM)
                                        .getPayload();
                            } catch (ConnectorException | IOException e) {
                                throw new CmpProcessingException(
                                        "COAP test client", e);
                            }
                        });
            }
        }
        throw new IllegalArgumentException(
                "invalid server path: " + serverPath);
    }

    // utility class, never create an instance
    private TestUtils() {

    }

}
