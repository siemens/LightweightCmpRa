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

import com.siemens.pki.cmpclientcomponent.configuration.RevocationContext;
import com.siemens.pki.lightweightcmpra.util.CredentialLoader;
import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class RevocationContextImpl implements RevocationContext {

    private URI cert;
    private BigInteger serialNumber;
    private String issuer;

    @Override
    public String getIssuer() {
        loadCert();
        return issuer;
    }

    @Override
    public BigInteger getSerialNumber() {
        loadCert();
        return serialNumber;
    }

    private void loadCert() {
        if (cert == null) {
            return;
        }
        final List<X509Certificate> certificates = CredentialLoader.loadCertificates(cert);
        if (certificates == null || certificates.isEmpty()) {
            return;
        }
        final X509Certificate firstCert = certificates.get(0);
        issuer = firstCert.getIssuerX500Principal().getName();
        serialNumber = firstCert.getSerialNumber();
    }

    public void setCert(final URI cert) {
        this.cert = cert;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }
}
