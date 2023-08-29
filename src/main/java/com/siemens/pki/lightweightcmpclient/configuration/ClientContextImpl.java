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

import com.siemens.pki.cmpclientcomponent.configuration.ClientContext;
import com.siemens.pki.cmpclientcomponent.configuration.EnrollmentContext;
import com.siemens.pki.cmpclientcomponent.configuration.RevocationContext;
import com.siemens.pki.lightweightcmpra.configuration.CertProfileConfigItem;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class ClientContextImpl extends CertProfileConfigItem implements ClientContext {

    private String recipient = ClientContext.super.getRecipient();

    private EnrollmentContext enrollmentContext;

    private RevocationContext revocationContext;

    @Override
    public EnrollmentContext getEnrollmentContext() {
        return enrollmentContext;
    }

    @Override
    public String getRecipient() {
        return recipient;
    }

    @Override
    public RevocationContext getRevocationContext() {
        return revocationContext;
    }

    public void setEnrollmentContext(final EnrollmentContextImpl enrollmentContext) {
        this.enrollmentContext = enrollmentContext;
    }

    public void setRecipient(final String recipient) {
        this.recipient = recipient;
    }

    public void setRevocationContext(final RevocationContextImpl revocationContext) {
        this.revocationContext = revocationContext;
    }
}
