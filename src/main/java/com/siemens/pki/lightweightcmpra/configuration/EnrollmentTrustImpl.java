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
import java.security.cert.PKIXRevocationChecker.Option;
import java.util.EnumSet;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class EnrollmentTrustImpl extends CertProfileBodyTypeConfigItem {

    private final VerificationContextImpl verificationContext = new VerificationContextImpl();

    public VerificationContextImpl getVerificationContext() {
        return verificationContext;
    }

    public void setAdditionalCerts(final URI[] additionalCerts) {
        verificationContext.setAdditionalCerts(additionalCerts);
    }

    public void setAIAsEnabled(final boolean aIAsEnabled) {
        verificationContext.setAIAsEnabled(aIAsEnabled);
    }

    public void setCDPsEnabled(final boolean cDPsEnabled) {
        verificationContext.setCDPsEnabled(cDPsEnabled);
    }

    public void setCRLs(final URI[] cRLs) {
        verificationContext.setCRLs(cRLs);
    }

    public void setOCSPResponder(final URI oCSPResponder) {
        verificationContext.setOCSPResponder(oCSPResponder);
    }

    public void setPKIXRevocationCheckerOptions(final EnumSet<Option> pKIXRevocationCheckerOptions) {
        verificationContext.setPKIXRevocationCheckerOptions(pKIXRevocationCheckerOptions);
    }

    public void setTrustedCertificates(final URI[] trustedCertificates) {
        verificationContext.setTrustedCertificates(trustedCertificates);
    }
}
