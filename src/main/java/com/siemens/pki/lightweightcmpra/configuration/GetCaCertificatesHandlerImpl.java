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

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;

import com.siemens.pki.cmpracomponent.configuration.GetCaCertificatesHandler;
import com.siemens.pki.lightweightcmpra.util.CredentialLoader;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class GetCaCertificatesHandlerImpl extends
        SupportMessageHandlerInterfaceImpl implements GetCaCertificatesHandler {

    private List<X509Certificate> certificateList;

    private URI[] caCertificates;

    public GetCaCertificatesHandlerImpl() {
        super(CMPObjectIdentifiers.id_it_caCerts.getId());
    }

    @Override
    public List<X509Certificate> getCaCertificates() {
        if (certificateList == null) {
            certificateList = CredentialLoader.loadCertificates(caCertificates);
        }
        return certificateList;

    }

    @XmlElement(required = true)
    public void setCaCertificates(final URI[] caCertificates) {
        this.caCertificates = caCertificates;
    }
}
