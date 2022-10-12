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
import javax.xml.bind.annotation.XmlElements;

import com.siemens.pki.cmpracomponent.configuration.CkgPasswordContext;
import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class CkgPasswordContextImpl implements CkgPasswordContext {

    private SharedSecretCredentialContextImpl EncryptionCredentials;

    private String KekAlg;

    @Override
    public SharedSecretCredentialContext getEncryptionCredentials() {
        return EncryptionCredentials;
    }

    @Override
    public String getKekAlg() {
        return computeDefaultIfNull(KekAlg,
                CkgPasswordContext.super::getKekAlg);
    }

    @XmlElements({
            @XmlElement(name = "SharedSecret", type = SharedSecretCredentialContextImpl.class, required = false)})
    public void setEncryptionCredentials(
            final SharedSecretCredentialContextImpl encryptionCredentials) {
        EncryptionCredentials = encryptionCredentials;
    }

    @XmlElement(required = true)
    public void setKekAlg(final String kekAlg) {
        KekAlg = kekAlg;
    }

}
