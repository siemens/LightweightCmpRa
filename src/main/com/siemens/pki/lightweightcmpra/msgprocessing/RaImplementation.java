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
package com.siemens.pki.lightweightcmpra.msgprocessing;

import javax.xml.bind.JAXB;

import com.siemens.pki.lightweightcmpra.config.xmlparser.Configuration.RaConfiguration;

/**
 * implementation of a RA composed from a {@link RaUpstream} and a
 * {@link RaDownstream}
 *
 */
public class RaImplementation {

    /**
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @throws Exception
     *             in case of error
     */
    public RaImplementation(final RaConfiguration config) throws Exception {
        final RaUpstream raUpstream = new RaUpstream(config.getUpstream());
        new RaDownstream(config.getDownstream(), raUpstream,
                config.getEnrollmentCredentials(),
                config.getUpstream().isEnforceRaVerified());
    }

}
