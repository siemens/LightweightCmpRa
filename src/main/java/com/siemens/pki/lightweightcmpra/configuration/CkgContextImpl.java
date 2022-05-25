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

import static com.siemens.pki.cmpracomponent.util.NullUtil.computeDefaultIfNull;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import com.siemens.pki.cmpracomponent.configuration.CkgContext;
import com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext;

@XmlAccessorType(XmlAccessType.PROPERTY)
abstract public class CkgContextImpl extends CertProfileBodyTypeConfigItem
        implements CkgContext {

    private SignatureCredentialContextImpl SigningCredentials;
    private String contentEncryptionAlg;

    @Override
    public String getContentEncryptionAlg() {
        return computeDefaultIfNull(contentEncryptionAlg,
                CkgContext.super::getContentEncryptionAlg);
    }

    @Override
    public SignatureCredentialContext getSigningCredentials() {
        return SigningCredentials;
    }

    public void setContentEncryptionAlg(final String contentEncryptionAlg) {
        this.contentEncryptionAlg = contentEncryptionAlg;
    }

    @XmlElement(name = "SignatureCredentials", required = true)
    public void setSigningCredentials(
            final SignatureCredentialContextImpl signingCredentials) {
        SigningCredentials = signingCredentials;
    }

}
