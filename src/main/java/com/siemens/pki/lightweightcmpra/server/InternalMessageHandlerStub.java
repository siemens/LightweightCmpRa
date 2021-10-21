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

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.xml.bind.JAXB;

import com.siemens.pki.lightweightcmpra.config.xmlparser.MESSAGEHANDLERCONFIGURATION;

/**
 *
 * stub to attach further downstream protocols in a generic manner
 */
public class InternalMessageHandlerStub {

    private static final Map<String, Function<InputStream, byte[]>> handlerMap =
            new HashMap<>();

    public static Function<InputStream, byte[]> getHandlerFunction(
            final String id) {
        return handlerMap.get(id);
    }

    /**
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @param messageHandler
     *            related downstream interface handler
     */
    public InternalMessageHandlerStub(final MESSAGEHANDLERCONFIGURATION config,
            final Function<InputStream, byte[]> messageHandler) {
        handlerMap.put(config.getId(), messageHandler);
    }

}
