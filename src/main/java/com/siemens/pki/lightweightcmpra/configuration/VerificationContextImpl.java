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
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.PKIXRevocationChecker.Option;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.lightweightcmpra.util.CredentialLoader;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class VerificationContextImpl implements VerificationContext {

    private URI[] AdditionalCerts;
    private URI[] CRLs;
    private URI OCSPResponder;
    private EnumSet<PKIXRevocationChecker.Option> PKIXRevocationCheckerOptions;
    private byte[] SharedSecret;
    private URI[] TrustedCertificates;
    private boolean AIAsEnabled;
    private boolean CDPsEnabled;

    private Collection<X509Certificate> AdditionalCertsAsCollection;
    private List<X509CRL> CRLsAsCollection;
    private Collection<X509Certificate> TrustedCertificatesAsCollection;

    @Override
    public Collection<X509Certificate> getAdditionalCerts() {
        if (AdditionalCertsAsCollection == null) {
            AdditionalCertsAsCollection =
                    CredentialLoader.loadCertificates(AdditionalCerts);
        }
        return AdditionalCertsAsCollection;
    }

    @Override
    public Collection<X509CRL> getCRLs() {
        if (CRLsAsCollection == null) {
            CRLsAsCollection = CredentialLoader.loadCRLs(CRLs);
        }
        return CRLsAsCollection;
    }

    @Override
    public URI getOCSPResponder() {
        return OCSPResponder;
    }

    @Override
    public EnumSet<Option> getPKIXRevocationCheckerOptions() {
        return PKIXRevocationCheckerOptions;
    }

    @Override
    public byte[] getSharedSecret(final byte[] senderKID) {
        return SharedSecret;
    }

    @Override
    public Collection<X509Certificate> getTrustedCertificates() {
        if (TrustedCertificatesAsCollection == null) {
            TrustedCertificatesAsCollection =
                    CredentialLoader.loadCertificates(TrustedCertificates);
        }
        return TrustedCertificatesAsCollection;
    }

    @Override
    public boolean isAIAsEnabled() {
        return AIAsEnabled;
    }

    @Override
    public boolean isCDPsEnabled() {
        return CDPsEnabled;
    }

    public void setAdditionalCerts(final URI[] additionalCerts) {
        AdditionalCerts = additionalCerts;
    }

    public void setAIAsEnabled(final boolean aIAsEnabled) {
        AIAsEnabled = aIAsEnabled;
    }

    public void setCDPsEnabled(final boolean cDPsEnabled) {
        CDPsEnabled = cDPsEnabled;
    }

    public void setCRLs(final URI[] cRLs) {
        CRLs = cRLs;
    }

    public void setOCSPResponder(final URI oCSPResponder) {
        OCSPResponder = oCSPResponder;
    }

    public void setPKIXRevocationCheckerOptions(
            final EnumSet<PKIXRevocationChecker.Option> pKIXRevocationCheckerOptions) {
        PKIXRevocationCheckerOptions = pKIXRevocationCheckerOptions;
    }

    public void setSharedSecret(final byte[] sharedSecret) {
        SharedSecret = sharedSecret;
    }

    public void setTrustedCertificates(final URI[] trustedCertificates) {
        TrustedCertificates = trustedCertificates;
    }

}
