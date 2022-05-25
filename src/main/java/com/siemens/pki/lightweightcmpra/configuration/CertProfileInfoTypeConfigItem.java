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

@XmlAccessorType(XmlAccessType.PROPERTY)
public abstract class CertProfileInfoTypeConfigItem {

    private String certProfile;

    private String infoTypeOid;

    protected CertProfileInfoTypeConfigItem(final String infoTypeOid) {
        setInfoTypeOid(infoTypeOid);
    }

    public String getCertProfile() {
        return certProfile;
    }

    public String getInfoTypeOid() {
        return infoTypeOid;
    }

    public void setCertProfile(final String certProfile) {
        this.certProfile = certProfile;
    }

    public void setInfoTypeOid(final String infoTypeOid) {
        this.infoTypeOid = infoTypeOid;
    }

    boolean matchesScope(final String certProfile, final String infoTypeOid) {
        if (this.infoTypeOid != null && !this.infoTypeOid.equals(infoTypeOid)
                || this.certProfile != null
                        && !this.certProfile.equals(certProfile)) {
            return false;
        }
        return true;
    }

}
