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

import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import java.util.regex.Pattern;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class NestedEndpointContextImpl implements NestedEndpointContext {

    private String recipientPattern;

    private VerificationContextImpl InputVerification;

    private CredentialContextImpl OutputCredentials;

    private String recipient;

    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }

    @Override
    public String getRecipient() {
        return recipient;
    }

    private Pattern recipientPatternAsPattern;

    @Override
    public VerificationContext getInputVerification() {
        return InputVerification;
    }

    @Override
    public CredentialContext getOutputCredentials() {
        return OutputCredentials;
    }

    public String getRecipientPattern() {
        return recipientPattern;
    }

    @Override
    public boolean isIncomingRecipientValid(final String recipient) {
        if (recipientPattern == null) {
            return true;
        }
        if (recipientPatternAsPattern == null) {
            recipientPatternAsPattern = Pattern.compile(recipientPattern);
        }
        return recipientPatternAsPattern.matcher(recipient).matches();
    }

    public void setInputVerification(final VerificationContextImpl inputVerification) {
        InputVerification = inputVerification;
    }

    @XmlElements({
        @XmlElement(name = "SharedSecret", type = SharedSecretCredentialContextImpl.class, required = false),
        @XmlElement(name = "Signature", type = SignatureCredentialContextImpl.class, required = false)
    })
    public void setOutputCredentials(final CredentialContextImpl outputCredentials) {
        OutputCredentials = outputCredentials;
    }

    public void setRecipientPattern(final String recipientPattern) {
        this.recipientPattern = recipientPattern;
    }
}
