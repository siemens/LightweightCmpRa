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

import com.siemens.pki.cmpclientcomponent.configuration.EnrollmentContext.TemplateExtension;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class TemplateExtensionImpl implements TemplateExtension {

    private byte[] value;
    private String id;

    private boolean critical;

    @Override
    public String getId() {
        return id;
    }

    @Override
    public byte[] getValue() {
        return value;
    }

    @Override
    public boolean isCritical() {
        return critical;
    }

    public void setCritical(final boolean critical) {
        this.critical = critical;
    }

    public void setId(final String id) {
        this.id = id;
    }

    public void setValue(final byte[] value) {
        this.value = value;
    }
}
