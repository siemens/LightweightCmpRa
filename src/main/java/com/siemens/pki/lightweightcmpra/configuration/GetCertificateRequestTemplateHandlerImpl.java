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
package com.siemens.pki.lightweightcmpra.configuration;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.cmpracomponent.configuration.GetCertificateRequestTemplateHandler;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class GetCertificateRequestTemplateHandlerImpl
        extends SupportMessageHandlerInterfaceImpl
        implements GetCertificateRequestTemplateHandler {

    private static final Logger LOGGER = LoggerFactory
            .getLogger(GetCertificateRequestTemplateHandlerImpl.class);

    private URI template;

    private byte[] templateBytes;

    public GetCertificateRequestTemplateHandlerImpl() {
        super(CMPObjectIdentifiers.id_it_certReqTemplate.getId());
    }

    @Override
    public byte[] getCertificateRequestTemplate() {
        if (templateBytes == null && template != null) {
            try (InputStream urlStream =
                    ConfigFileLoader.getConfigUriAsStream(template)) {
                templateBytes = urlStream.readAllBytes();
            } catch (final IOException e1) {
                final String msg = "error loading template from " + template;
                LOGGER.error(msg, e1);
                throw new RuntimeException(msg, e1);
            }
        }
        return templateBytes;
    }

    public URI getTemplate() {
        return template;
    }

    @XmlElement(required = true)
    public void setTemplate(final URI template) {
        this.template = template;
    }

}
