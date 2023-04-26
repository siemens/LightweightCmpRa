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

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;
import java.io.IOException;
import java.io.InputStream;

public class YamlConfigLoader {

    private static final ObjectMapper JACKSON_OBJECT_MAPPER = YAMLMapper.builder()
            .enable(
                    MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS,
                    MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES,
                    MapperFeature.ACCEPT_CASE_INSENSITIVE_VALUES)
            .build()
            .registerModules(new JaxbAnnotationModule())
            .setSerializationInclusion(Include.NON_EMPTY);

    public static ConfigurationImpl loadConfig(final String filename) throws IOException {
        try (InputStream is = ConfigFileLoader.getConfigFileAsStream(filename)) {
            return JACKSON_OBJECT_MAPPER.readValue(is, ConfigurationImpl.class);
        }
    }

    private YamlConfigLoader() {}
}
