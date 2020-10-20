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
package com.siemens.pki.lightweightcmpra.test;

import java.io.File;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;

import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.main.RA;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;
import com.siemens.pki.lightweightcmpra.protection.SignatureBasedProtection;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;

public class CmpTestcaseBase {

    static public final File CONFIG_DIRECTORY = new File(
            "./src/test/java/com/siemens/pki/lightweightcmpra/test/config");
    private static ThreadGroup lraThreadGroup =
            new ThreadGroup("LRA Thread Group");
    private static ProtectionProvider eeSignaturebasedProtectionProvider;

    private static Set<String> startedRAs = new HashSet<>();

    private static Map<String, Function<PKIMessage, PKIMessage>> startedEeClients =
            new HashMap<>();

    protected static ProtectionProvider getEeSignaturebasedProtectionProvider() {
        return eeSignaturebasedProtectionProvider;
    }

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        Security.addProvider(CertUtility.BOUNCY_CASTLE_PROVIDER);
        ConfigFileLoader.setConfigFileBase(CONFIG_DIRECTORY);
        eeSignaturebasedProtectionProvider =
                new SignatureBasedProtection("credentials/CMP_EE_Keystore.p12",
                        TestUtils.PASSWORD_AS_CHAR_ARRAY);
    }

    private Function<PKIMessage, PKIMessage> eeSignatureBasedCmpClient;

    protected Function<PKIMessage, PKIMessage> getEeSignatureBasedCmpClient() {
        return eeSignatureBasedCmpClient;
    }

    protected void initTestbed(final String nameOfRaConfigFile,
            final String cmpClientUrl)
            throws Exception, GeneralSecurityException, InterruptedException {
        if (cmpClientUrl != null) {
            eeSignatureBasedCmpClient = startedEeClients.get(cmpClientUrl);
            if (eeSignatureBasedCmpClient == null) {
                eeSignatureBasedCmpClient =
                        TestUtils.createCmpClient(cmpClientUrl);
                startedEeClients.put(cmpClientUrl, eeSignatureBasedCmpClient);
            }
        }
        if (!startedRAs.contains(nameOfRaConfigFile)) {
            final Thread raMainTread = new Thread(lraThreadGroup,
                    () -> RA.init(nameOfRaConfigFile),
                    "LRA Main Thread for " + nameOfRaConfigFile);
            raMainTread.start();
            raMainTread.join();
            startedRAs.add(nameOfRaConfigFile);
        }
    }

}
