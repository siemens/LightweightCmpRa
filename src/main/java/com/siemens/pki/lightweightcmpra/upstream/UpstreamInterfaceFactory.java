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
package com.siemens.pki.lightweightcmpra.upstream;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.configuration.AbstractUpstreamInterfaceConfig;
import com.siemens.pki.lightweightcmpra.configuration.HttpClientConfig;
import com.siemens.pki.lightweightcmpra.configuration.HttpsClientConfig;
import com.siemens.pki.lightweightcmpra.configuration.OfflineFileClientConfig;
import com.siemens.pki.lightweightcmpra.upstream.offline.FileOfflineClient;
import com.siemens.pki.lightweightcmpra.upstream.online.HttpSession;
import com.siemens.pki.lightweightcmpra.upstream.online.HttpsSession;

public class UpstreamInterfaceFactory {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(UpstreamInterfaceFactory.class);

    /**
     * create an {@link UpstreamInterface} instance according to the given
     * configuration
     *
     * @param configuration
     *            upstream interface configuration
     * @return an upstream instance
     */
    public static UpstreamInterface create(
            final AbstractUpstreamInterfaceConfig configuration) {
        try {
            if (configuration instanceof OfflineFileClientConfig) {
                return new FileOfflineClient(
                        (OfflineFileClientConfig) configuration);
            }
            if (configuration instanceof HttpClientConfig) {
                final HttpClientConfig httpConfig =
                        (HttpClientConfig) configuration;
                final URI ServingUri = httpConfig.getServingUri();
                final String scheme = ServingUri.getScheme();
                if ("http".equalsIgnoreCase(scheme)) {
                    return new HttpSession(ServingUri.toURL());
                }
                if ("https".equalsIgnoreCase(scheme)
                        && httpConfig instanceof HttpsClientConfig) {
                    return new HttpsSession(ServingUri.toURL(),
                            (HttpsClientConfig) httpConfig);
                }
            }
            LOGGER.error(
                    "error creating upstream interface from given configuration");
        } catch (final Exception e) {
            LOGGER.error(
                    "error creating upstream interface from given configuration",
                    e);
        }
        return null;
    }

    private UpstreamInterfaceFactory() {

    }

}
