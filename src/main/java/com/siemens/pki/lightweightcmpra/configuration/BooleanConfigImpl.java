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

import java.util.function.BooleanSupplier;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

/**
 * boolean configuration items
 */
@XmlAccessorType(XmlAccessType.PROPERTY)
public class BooleanConfigImpl extends CertProfileBodyTypeConfigItem
        implements BooleanSupplier {

    private Boolean value = false;

    @Override
    public boolean getAsBoolean() {
        return value;
    }

    public void setValue(final Boolean value) {
        this.value = value;
    }
}
