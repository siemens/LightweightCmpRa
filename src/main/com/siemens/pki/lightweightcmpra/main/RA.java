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

import java.io.InputStream;
import java.security.Security;

import javax.xml.bind.JAXB;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    /**
     * @param configStream
     *            XML configuration as stream
     * @throws Exception
     */
    public static void init(final InputStream configStream) throws Exception {
        Security.addProvider(CertUtility.BOUNCY_CASTLE_PROVIDER);
        final Configuration configuration =
                JAXB.unmarshal(configStream, Configuration.class);
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
    }

    /**
     * @param nameOfConfigFile
     *            XMl configuration file
     */
    public static void init(final String nameOfConfigFile) {
        try (InputStream configStream =
                ConfigFileLoader.getConfigFileAsStream(nameOfConfigFile)) {
            init(configStream);
        } catch (final Exception ex) {
            LOGGER.error("could not load configuration", ex);
        }
    }

    /**
     * @param args
     *            command line arguments. Call with <name of XML config file> as
     *            the only parameter
     */
    public static void main(final String[] args) {
        if (args == null || args.length != 1) {
            System.err.println(
                    "call with <name of XML config file> as the only parameter");
            return;
        }
        init(args[0]);
    }

}
