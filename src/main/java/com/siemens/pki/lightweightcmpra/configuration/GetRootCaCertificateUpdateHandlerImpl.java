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

import com.siemens.pki.cmpracomponent.configuration.GetRootCaCertificateUpdateHandler;
import com.siemens.pki.lightweightcmpra.util.CredentialLoader;
import java.net.URI;
import java.security.cert.X509Certificate;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class GetRootCaCertificateUpdateHandlerImpl extends SupportMessageHandlerInterfaceImpl
        implements GetRootCaCertificateUpdateHandler {

    private URI newWithNew;

    private URI newWithOld;
    private URI oldWithNew;
    private RootCaCertificateUpdateResponse response;

    public GetRootCaCertificateUpdateHandlerImpl() {
        super(CMPObjectIdentifiers.id_it_rootCaCert.getId());
    }

    public URI getNewWithNew() {
        return newWithNew;
    }

    public URI getNewWithOld() {
        return newWithOld;
    }

    public URI getOldWithNew() {
        return oldWithNew;
    }

    @Override
    public RootCaCertificateUpdateResponse getRootCaCertificateUpdate(final X509Certificate oldRootCaCertificate) {
        if (response == null) {
            response = new RootCaCertificateUpdateResponse() {
                private final X509Certificate newWithNewCert = loadCertFromUri(newWithNew);

                private final X509Certificate newWithOldCert = loadCertFromUri(newWithOld);

                private final X509Certificate oldWithNewCert = loadCertFromUri(oldWithNew);

                @Override
                public X509Certificate getNewWithNew() {
                    return newWithNewCert;
                }

                @Override
                public X509Certificate getNewWithOld() {
                    return newWithOldCert;
                }

                @Override
                public X509Certificate getOldWithNew() {
                    return oldWithNewCert;
                }
            };
        }
        return response;
    }

    public void setNewWithNew(final URI newWithNew) {
        this.newWithNew = newWithNew;
    }

    public void setNewWithOld(final URI newWithOld) {
        this.newWithOld = newWithOld;
    }

    public void setOldWithOld(final URI oldWithOld) {
        this.oldWithNew = oldWithOld;
    }

    private X509Certificate loadCertFromUri(final URI uri) {
        if (uri == null) {
            return null;
        }
        return CredentialLoader.loadCertificates(uri).get(0);
    }
}
