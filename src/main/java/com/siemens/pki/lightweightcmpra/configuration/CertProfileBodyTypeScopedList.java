/*
 *  Copyright (c) 2023 Siemens AG
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

import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertProfileBodyTypeScopedList<T extends CertProfileBodyTypeConfigItem> extends ArrayList<T> {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertProfileBodyTypeScopedList.class);

    private static final long serialVersionUID = 1L;

    public T getMatchingConfig(final String certProfile, final int bodyType) {
        for (final T aktItem : this) {
            if (aktItem.matchesScope(certProfile, bodyType)) {
                return aktItem;
            }
        }
        return null;
    }

    public T getMatchingConfig(final String certProfile, final int bodyType, final String itemName) {
        final T ret = getMatchingConfig(certProfile, bodyType);
        if (ret != null) {
            return ret;
        }
        LOGGER.error(
                "no matching " + itemName + " entry found for certProfile: " + certProfile + ", bodyType: " + bodyType);
        return null;
    }
}
