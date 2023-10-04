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

import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.lightweightcmpra.main.RA;
import com.siemens.pki.lightweightcmpra.test.framework.CertUtility;
import com.siemens.pki.lightweightcmpra.test.framework.TestUtils;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;
import java.io.File;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.AfterClass;
import org.junit.BeforeClass;

public class CmpTestcaseBase {

    public static final File CONFIG_DIRECTORY =
            new File("./src/test/java/com/siemens/pki/lightweightcmpra/test/config");
    private static ProtectionProvider eeSignaturebasedProtectionProvider;

    private static Map<String, Function<PKIMessage, PKIMessage>> startedEeClients = new HashMap<>();

    private static Function<PKIMessage, PKIMessage> eeCmpClient;

    protected static ProtectionProvider getEeSignaturebasedProtectionProvider() {
        return eeSignaturebasedProtectionProvider;
    }

    protected static void initTestbed(final String cmpClientUrl, final String... namesOfRaConfigFile)
            throws Exception, GeneralSecurityException, InterruptedException {
        if (cmpClientUrl != null) {
            eeCmpClient = startedEeClients.get(cmpClientUrl);
            if (eeCmpClient == null) {
                eeCmpClient = TestUtils.createCmpClient(cmpClientUrl);
                startedEeClients.put(cmpClientUrl, eeCmpClient);
            }
        }
        for (final String nameOfRaConfigFile : namesOfRaConfigFile) {
            RA.main(new String[] {nameOfRaConfigFile});
        }
    }

    @BeforeClass
    public static void setUpProvider() throws Exception {
        Security.addProvider(CertUtility.BOUNCY_CASTLE_PROVIDER);
        ConfigFileLoader.setConfigFileBase(CONFIG_DIRECTORY);
        eeSignaturebasedProtectionProvider = TestUtils.createSignatureBasedProtection(
                // "credentials/CMP_EE_Keystore_EdDSA.p12",
                "credentials/CMP_EE_Keystore.p12", TestUtils.getPasswordAsCharArray());
    }

    @AfterClass
    public static void shutdownAllRas() {
        RA.stopAllRas();
    }

    protected Function<PKIMessage, PKIMessage> getEeCmpClient() {
        return eeCmpClient;
    }
}
