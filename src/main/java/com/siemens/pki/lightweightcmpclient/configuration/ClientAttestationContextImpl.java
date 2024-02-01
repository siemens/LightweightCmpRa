/*
 *  Copyright (c) 2024 Siemens AG
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
package com.siemens.pki.lightweightcmpclient.configuration;

import com.siemens.pki.cmpclientcomponent.configuration.ClientAttestationContext;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;
import java.io.IOException;
import java.net.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ClientAttestationContextImpl implements ClientAttestationContext {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientAttestationContextImpl.class);

    private URI evidenceSource;

    public URI getEvidenceSource() {
        return evidenceSource;
    }

    @Override
    public byte[] getEvidenceStatement(byte[] attestationNonce) {
        try {
            return ConfigFileLoader.getConfigUriAsStream(evidenceSource).readAllBytes();
        } catch (final IOException e) {
            LOGGER.error("error loading evidence from " + evidenceSource, e);
            return null;
        }
    }

    public void setEvidenceSource(URI evidenceSource) {
        this.evidenceSource = evidenceSource;
    }
}
