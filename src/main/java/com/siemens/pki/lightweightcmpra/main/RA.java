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

import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.lightweightcmpra.configuration.ConfigurationImpl;
import com.siemens.pki.lightweightcmpra.configuration.YamlConfigLoader;
import com.siemens.pki.lightweightcmpra.downstream.DownstreamInterface;
import com.siemens.pki.lightweightcmpra.downstream.DownstreamInterfaceFactory;
import com.siemens.pki.lightweightcmpra.upstream.UpstreamInterface;
import com.siemens.pki.lightweightcmpra.upstream.UpstreamInterfaceFactory;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * main class
 *
 */
public class RA {

    private static class CertProfileBodyTypeTupel {
        private final String certProfile;
        private final int bodyType;

        CertProfileBodyTypeTupel(final String certProfile, final int bodyType) {
            this.certProfile = certProfile;
            this.bodyType = bodyType;
        }

        @Override
        public boolean equals(final Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            final CertProfileBodyTypeTupel other = (CertProfileBodyTypeTupel) obj;
            return bodyType == other.bodyType && Objects.equals(certProfile, other.certProfile);
        }

        @Override
        public int hashCode() {
            return Objects.hash(bodyType, certProfile);
        }
    }

    static class DeferredSupplier<T> implements Supplier<T> {
        T val;

        @Override
        public T get() {
            return val;
        }

        void set(final T val) {
            this.val = val;
        }
    }

    private static ArrayList<RA> raList;

    /**
     * @param args command line arguments. Call with &lt;name of XML/YAML/JSON
     *             config file&gt;,
     * @throws Exception if startup of at least one RA instance failed
     */
    public static void main(final String[] args) throws Exception {
        if (args == null || args.length < 1) {
            System.err.println("call with <name of YAML/JSON config file>");
            return;
        }
        raList = new ArrayList<>(args.length);
        // start RAs
        for (final String actConfigFile : args) {
            raList.add(new RA(actConfigFile));
        }
    }

    /**
     * stop all RA instances, used for unit tests
     */
    public static void stopAllRas() {
        for (; ; ) {
            if (raList.isEmpty()) {
                break;
            }
            raList.remove(0).stop();
        }
    }

    private DownstreamInterface downstreamInterface;
    private String configFile;

    private RA(final String actConfigFile) throws Exception {
        configFile = actConfigFile;

        try {
            final ConfigurationImpl configuration = YamlConfigLoader.loadConfig(configFile, ConfigurationImpl.class);
            final DeferredSupplier<CmpRaInterface> raHolder = new DeferredSupplier<>();
            final Map<CertProfileBodyTypeTupel, UpstreamInterface> upstreamInterfaceMap = new HashMap<>();
            final UpstreamExchange upstreamExchange = (request, certProfile, bodyTypeOfFirstRequest) -> {
                final CertProfileBodyTypeTupel key = new CertProfileBodyTypeTupel(certProfile, bodyTypeOfFirstRequest);
                UpstreamInterface upstreamInterface = upstreamInterfaceMap.get(key);
                if (upstreamInterface == null) {
                    upstreamInterface = UpstreamInterfaceFactory.create(
                            configuration.getUpstreamInterface(certProfile, bodyTypeOfFirstRequest));
                    upstreamInterface.setDelayedResponseHandler(raHolder.get()::gotResponseAtUpstream);
                    upstreamInterfaceMap.put(key, upstreamInterface);
                }
                return upstreamInterface.apply(request, certProfile);
            };
            final CmpRaInterface raComponent =
                    CmpRaComponent.instantiateCmpRaComponent(configuration, upstreamExchange);
            raHolder.set(raComponent);
            downstreamInterface = DownstreamInterfaceFactory.create(
                    configuration.getDownstreamInterface(), raComponent::processRequest);
            System.out.println("RA configured with " + configFile + " is up and running");
        } catch (final Exception ex) {
            System.err.println("start of RA configured with " + configFile + " failed");
            throw ex;
        }
    }

    private void stop() {
        if (downstreamInterface != null) {
            downstreamInterface.stop();
        }
        System.out.println("RA configured with " + configFile + " stopped");
    }
}
