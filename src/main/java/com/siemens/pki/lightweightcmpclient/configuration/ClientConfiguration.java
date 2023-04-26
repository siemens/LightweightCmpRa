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
package com.siemens.pki.lightweightcmpclient.configuration;

import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.lightweightcmpra.configuration.AbstractUpstreamInterfaceConfig;
import com.siemens.pki.lightweightcmpra.configuration.CertProfileBodyTypeScopedList;
import com.siemens.pki.lightweightcmpra.configuration.CmpMessageInterfaceImpl;
import com.siemens.pki.lightweightcmpra.configuration.CoapClientConfig;
import com.siemens.pki.lightweightcmpra.configuration.HttpClientConfig;
import com.siemens.pki.lightweightcmpra.configuration.HttpsClientConfig;
import com.siemens.pki.lightweightcmpra.configuration.OfflineFileClientConfig;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * CMP client implementation
 *
 */
@XmlRootElement
// {@link java.util.List} sub classing works only with {@link XmlAccessType}.FIELD
@XmlAccessorType(XmlAccessType.FIELD)
public class ClientConfiguration {

    @XmlElements({
        @XmlElement(name = "OfflineFileClient", type = OfflineFileClientConfig.class, required = false),
        @XmlElement(name = "HttpClient", type = HttpClientConfig.class, required = false),
        @XmlElement(name = "HttpsClient", type = HttpsClientConfig.class, required = false),
        @XmlElement(name = "CoapClient", type = CoapClientConfig.class, required = false),
    })
    private final CertProfileBodyTypeScopedList<AbstractUpstreamInterfaceConfig> MessageInterface =
            new CertProfileBodyTypeScopedList<>();

    private final CertProfileBodyTypeScopedList<CmpMessageInterfaceImpl> MessageConfiguration =
            new CertProfileBodyTypeScopedList<>();

    private final CertProfileScopedList<ClientContextImpl> ClientContext = new CertProfileScopedList<>();

    public ClientContextImpl getClientContext(final String certProfile) {
        return ClientContext.getMatchingConfig(certProfile, "ClientContext");
    }

    public CmpMessageInterface getMessageConfiguration(final String certProfile, final int bodyType) {
        return MessageConfiguration.getMatchingConfig(certProfile, bodyType, "MessageConfiguration");
    }

    public AbstractUpstreamInterfaceConfig getMessageInterface(final String certProfile, final int bodyType) {
        return MessageInterface.getMatchingConfig(certProfile, bodyType, "MessageInterface");
    }
}
