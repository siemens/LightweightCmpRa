/*
 *  Copyright (c) 2020 Siemens AG
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
package com.siemens.pki.lightweightcmpra.main;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Security;

import javax.xml.bind.JAXB;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;
import com.siemens.pki.lightweightcmpra.config.xmlparser.Configuration;
import com.siemens.pki.lightweightcmpra.config.xmlparser.Configuration.RaConfiguration;
import com.siemens.pki.lightweightcmpra.config.xmlparser.Configuration.RestService;
import com.siemens.pki.lightweightcmpra.config.xmlparser.Configuration.ServiceConfiguration;
import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.msgprocessing.RaImplementation;
import com.siemens.pki.lightweightcmpra.msgprocessing.RestServiceImplementation;
import com.siemens.pki.lightweightcmpra.msgprocessing.ServiceImplementation;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;

/**
 * main class
 *
 */
public class RA {

    private static final Logger LOGGER = LoggerFactory.getLogger(RA.class);
    private static final ObjectMapper JACKSON_OBJECT_MAPPER =
            new ObjectMapper(new YAMLFactory())
                    .registerModules(new JaxbAnnotationModule())
                    .setSerializationInclusion(Include.NON_EMPTY);

    /**
     * @param configStream
     *            XML/JSON/YAML configuration as stream
     * @return the loaded configuration tree
     * @throws Exception
     *             in case of errors while loading the configuration
     */
    public static Configuration init(final InputStream configStream)
            throws Exception {
        Security.addProvider(CertUtility.BOUNCY_CASTLE_PROVIDER);
        final InputStream bufConfigStream;
        if (!configStream.markSupported()) {
            bufConfigStream = new BufferedInputStream(configStream);
        } else {
            bufConfigStream = configStream;
        }
        bufConfigStream.mark(1000);
        boolean isXmlInput = false;
        final BufferedReader br =
                new BufferedReader(new InputStreamReader(bufConfigStream));
        for (String line; (line = br.readLine()) != null;) {
            if (line.trim().startsWith("<")) {
                isXmlInput = true;
                break;
            }
            if (!line.isBlank()) {
                break;
            }
        }
        bufConfigStream.reset();
        final Configuration configuration;
        if (isXmlInput) {
            configuration =
                    JAXB.unmarshal(bufConfigStream, Configuration.class);
        } else {
            configuration = JACKSON_OBJECT_MAPPER.readValue(bufConfigStream,
                    Configuration.class);
        }

        for (final RaConfiguration aktRaConfig : configuration
                .getRaConfiguration()) {
            new RaImplementation(aktRaConfig);
        }
        for (final ServiceConfiguration aktServiceConfig : configuration
                .getServiceConfiguration()) {
            new ServiceImplementation(aktServiceConfig);
        }
        for (final RestService aktRestService : configuration
                .getRestService()) {
            new RestServiceImplementation(aktRestService);
        }
        LOGGER.info("RA up and running");
        return configuration;
    }

    /**
     * @param nameOfConfigFile
     *            XMl configuration file
     * @return the loaded configuration tree
     */
    public static Configuration init(final String nameOfConfigFile) {
        try (InputStream configStream =
                ConfigFileLoader.getConfigFileAsStream(nameOfConfigFile)) {
            return init(configStream);
        } catch (final Exception ex) {
            LOGGER.error("could not load configuration", ex);
            return null;
        }
    }

    /**
     * @param args
     *            command line arguments. Call with &lt;name of XML/YAML/JSON
     *            config file&gt;, [&lt;name of config file converted to
     *            YAML&gt;]
     */
    public static void main(final String[] args) {
        if (args == null || args.length < 1) {
            System.err.println(
                    "call with <name of XML/YAML/JSON config file> [<name of config file converted to YAML>]");
            return;
        }
        final Configuration configuration = init(args[0]);
        if (configuration != null && args.length >= 2) {
            try {
                JACKSON_OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
                        .writeValue(new File(args[1]), configuration);
            } catch (final IOException e) {
                LOGGER.warn("could not write converted YAML file", e);
            }
        }
    }

}
