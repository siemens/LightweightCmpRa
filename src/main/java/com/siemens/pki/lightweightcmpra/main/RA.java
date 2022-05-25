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

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import java.util.ArrayList;

import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.lightweightcmpra.configuration.ConfigurationImpl;
import com.siemens.pki.lightweightcmpra.configuration.YamlConfigLoader;
import com.siemens.pki.lightweightcmpra.downstream.DownstreamInterface;
import com.siemens.pki.lightweightcmpra.downstream.DownstreamInterfaceFactory;
import com.siemens.pki.lightweightcmpra.upstream.UpstreamInterface;
import com.siemens.pki.lightweightcmpra.upstream.UpstreamInterfaceFactory;

/**
 * main class
 *
 */
public class RA {

    /**
     * @param args
     *            command line arguments. Call with &lt;name of XML/YAML/JSON
     *            config file&gt;,
     * @throws Exception
     */
    public static void main(final String[] args) throws Exception {
        if (args == null || args.length < 1) {
            System.err.println("call with <name of YAML/JSON config file>");
            return;
        }
        final ArrayList<Thread> threadList = new ArrayList<>(args.length);
        // start RAs
        for (final String actConfigFile : args) {
            threadList.add(startOneRa(actConfigFile));
        }
        // wait for complete initialization
        for (final Thread aktThread : threadList) {
            aktThread.join();
        }
    }

    private static Thread startOneRa(final String actConfigFile) {
        final String threadName = "RA->" + actConfigFile;
        final ThreadGroup tg = new ThreadGroup(
                Thread.currentThread().getThreadGroup(), threadName);
        final Thread raThread = new Thread(tg, () -> {
            try {
                final ConfigurationImpl configuration =
                        YamlConfigLoader.loadConfig(actConfigFile);
                final UpstreamInterface upstreamInterface =
                        ifNotNull(configuration.getUpstreamInterface(),
                                UpstreamInterfaceFactory::create);
                final CmpRaInterface raComponent =
                        CmpRaComponent.instantiateCmpRaComponent(configuration,
                                upstreamInterface);
                if (upstreamInterface != null) {
                    upstreamInterface.setDelayedResponseHandler(
                            raComponent::gotResponseAtUpstream);
                }
                @SuppressWarnings("unused")
                final DownstreamInterface downstreamInterface =
                        DownstreamInterfaceFactory.create(
                                configuration.getDownstreamInterface(),
                                raComponent::processRequest);
                System.out.println("RA configured with " + actConfigFile
                        + " is up and running");
            } catch (final Exception ex) {
                System.err.println("start of RA configured with "
                        + actConfigFile + " failed");
                ex.printStackTrace();
            }
        }, threadName);
        raThread.start();
        return raThread;
    }

}
