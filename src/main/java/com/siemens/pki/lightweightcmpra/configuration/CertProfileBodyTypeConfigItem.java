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
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlAccessorType(XmlAccessType.PROPERTY)
abstract public class CertProfileBodyTypeConfigItem {

    private String certProfile;
    private Integer bodyType;

    public Integer getBodyType() {
        return bodyType;
    }

    public String getCertProfile() {
        return certProfile;
    }

    @XmlJavaTypeAdapter(XmlPkiMessageTypeToIntAdapter.class)
    public void setBodyType(final Integer bodyType) {
        this.bodyType = bodyType;
    }

    public void setCertProfile(final String certProfile) {
        this.certProfile = certProfile;
    }

    boolean matchesScope(final String certProfile, final int bodyType) {
        if (this.bodyType != null && !this.bodyType.equals(bodyType)
                || this.certProfile != null
                        && !this.certProfile.equals(certProfile)) {
            return false;
        }
        return true;
    }

}
