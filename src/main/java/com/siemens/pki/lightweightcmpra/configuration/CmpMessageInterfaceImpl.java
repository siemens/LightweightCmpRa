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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;

import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class CmpMessageInterfaceImpl extends CertProfileBodyTypeConfigItem
        implements CmpMessageInterface {

    private VerificationContextImpl VerificationContext;

    private NestedEndpointContextImpl NestedEndpointContext;

    private CredentialContextImpl OutputCredentials;

    private ReprotectMode ReprotectMode =
            CmpMessageInterface.ReprotectMode.reprotect;

    private boolean SuppressRedundantExtraCerts;

    private boolean CacheExtraCerts;

    private long allowedMessageTimDeviation = 3600;

    @Override
    public VerificationContext getInputVerification() {
        return VerificationContext;
    }

    @Override
    public NestedEndpointContext getNestedEndpointContext() {
        return NestedEndpointContext;
    }

    @Override
    public CredentialContext getOutputCredentials() {
        return OutputCredentials;
    }

    @Override
    public ReprotectMode getReprotectMode() {
        return ReprotectMode;
    }

    @Override
    public boolean getSuppressRedundantExtraCerts() {
        return SuppressRedundantExtraCerts;
    }

    @Override
    public boolean isCacheExtraCerts() {
        return CacheExtraCerts;
    }

    @Override
    public boolean isMessageTimeDeviationAllowed(final long deviation) {
        return Math.abs(deviation) <= allowedMessageTimDeviation;
    }

    public void setAllowedMessageTimeDeviation(
            final long messageTimeDeviationAllowed) {
        allowedMessageTimDeviation = messageTimeDeviationAllowed;
    }

    public void setCacheExtraCerts(final boolean cacheExtraCerts) {
        CacheExtraCerts = cacheExtraCerts;
    }

    public void setNestedEndpointContext(
            final NestedEndpointContextImpl nestedEndpointContext) {
        NestedEndpointContext = nestedEndpointContext;
    }

    @XmlElements({
            @XmlElement(name = "SharedSecret", type = SharedSecretCredentialContextImpl.class, required = false),
            @XmlElement(name = "Signature", type = SignatureCredentialContextImpl.class, required = false)})
    public void setOutputCredentials(
            final CredentialContextImpl outputCredentials) {
        OutputCredentials = outputCredentials;
    }

    @XmlElement(required = true)
    public void setReprotectMode(final ReprotectMode reprotectMode) {
        ReprotectMode = reprotectMode;
    }

    public void setSuppressRedundantExtraCerts(
            final boolean suppressRedundantExtraCerts) {
        SuppressRedundantExtraCerts = suppressRedundantExtraCerts;
    }

    public void setVerificationContext(
            final VerificationContextImpl verificationContext) {
        VerificationContext = verificationContext;
    }

}
