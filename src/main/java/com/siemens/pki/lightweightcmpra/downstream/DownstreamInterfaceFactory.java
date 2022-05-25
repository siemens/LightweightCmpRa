/*
 *  Copyright (c) 2022 Siemens AG
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
package com.siemens.pki.lightweightcmpra.downstream;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.configuration.AbstractDownstreamInterfaceConfig;
import com.siemens.pki.lightweightcmpra.configuration.CoapServerConfig;
import com.siemens.pki.lightweightcmpra.configuration.HttpServerConfig;
import com.siemens.pki.lightweightcmpra.configuration.HttpsServerConfig;
import com.siemens.pki.lightweightcmpra.configuration.OfflineFileServerConfig;
import com.siemens.pki.lightweightcmpra.downstream.offline.OfflineFileServer;
import com.siemens.pki.lightweightcmpra.downstream.online.CmpCoapServer;
import com.siemens.pki.lightweightcmpra.downstream.online.CmpHttpServer;

public class DownstreamInterfaceFactory {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(DownstreamInterfaceFactory.class);

    /**
     * create an {@link DownstreamInterface} instance according to the given
     * configuration
     *
     * @param configuration
     *            downstream interface configuration
     * @param requestHandler
     *            RA handling incoming requests
     * @return
     */
    public static DownstreamInterface create(
            final AbstractDownstreamInterfaceConfig configuration,
            final DownstreamInterface.ExFunction requestHandler) {
        try {
            if (configuration instanceof OfflineFileServerConfig) {
                return new OfflineFileServer(
                        (OfflineFileServerConfig) configuration,
                        requestHandler);
            }
            if (configuration instanceof HttpServerConfig) {
                final HttpServerConfig httpConfig =
                        (HttpServerConfig) configuration;
                final URI ServingUri = httpConfig.getServingUri();
                final String scheme = ServingUri.getScheme();
                if ("http".equalsIgnoreCase(scheme)) {
                    return new CmpHttpServer(ServingUri.toURL(),
                            requestHandler);
                }
                if ("https".equalsIgnoreCase(scheme)
                        && httpConfig instanceof HttpsServerConfig) {
                    return new CmpHttpServer(ServingUri.toURL(), requestHandler,
                            (HttpsServerConfig) httpConfig);
                }
            }
            if (configuration instanceof CoapServerConfig) {
                return new CmpCoapServer((CoapServerConfig) configuration,
                        requestHandler);
            }
            LOGGER.error(
                    "error creating downstream interface from given configuration");
        } catch (final Exception e) {
            LOGGER.error(
                    "error creating downstream interface from given configuration",
                    e);
        }
        return null;
    }

    private DownstreamInterfaceFactory() {

    }

}
