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
package com.siemens.pki.lightweightcmpclient.configuration;

import com.siemens.pki.lightweightcmpra.configuration.CertProfileConfigItem;
import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertProfileScopedList<T extends CertProfileConfigItem> extends ArrayList<T> {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertProfileScopedList.class);

    private static final long serialVersionUID = 1L;

    public T getMatchingConfig(final String certProfile) {
        for (final T aktItem : this) {
            if (aktItem.matchesCertProfile(certProfile)) {
                return aktItem;
            }
        }
        return null;
    }

    public T getMatchingConfig(final String certProfile, final String itemName) {
        final T ret = getMatchingConfig(certProfile);
        if (ret != null) {
            return ret;
        }
        LOGGER.error("no matching " + itemName + " entry found for certProfile: " + certProfile);
        return null;
    }
}
