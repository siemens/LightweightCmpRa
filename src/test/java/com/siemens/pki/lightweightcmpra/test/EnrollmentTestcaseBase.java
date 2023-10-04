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

import com.siemens.pki.lightweightcmpra.test.framework.CmpCaMock;
import com.siemens.pki.lightweightcmpra.test.framework.KeyPairGeneratorFactory;
import com.siemens.pki.lightweightcmpra.test.framework.TestUtils;
import com.siemens.pki.lightweightcmpra.test.framework.TrustChainAndPrivateKey;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EnrollmentTestcaseBase extends CmpTestcaseBase {

    private static KeyPairGenerator keyGenerator;

    public static final Logger LOGGER = LoggerFactory.getLogger(EnrollmentTestcaseBase.class);

    private static TrustChainAndPrivateKey enrollmentCredentials;

    protected static KeyPairGenerator getKeyGenerator() {
        return keyGenerator;
    }

    protected static void initTestbed(final String cmpClientUrl, final String... namesOfRaConfigFile)
            throws Exception, GeneralSecurityException, InterruptedException {
        CmpTestcaseBase.initTestbed(cmpClientUrl, namesOfRaConfigFile);
        if (enrollmentCredentials == null) {
            enrollmentCredentials =
                    new TrustChainAndPrivateKey("credentials/ENROLL_Keystore.p12", TestUtils.getPasswordAsCharArray());
        }
        if (keyGenerator == null) {
            keyGenerator = KeyPairGeneratorFactory.getEcKeyPairGenerator("secp256r1");
            // keyGenerator = KeyPairGeneratorFactory.getRsaKeyPairGenerator(2048);
        }
    }

    @BeforeClass
    public static void launchCa() throws InterruptedException {
        CmpCaMock.launchSingleCaMock();
    }

    @AfterClass
    public static void shutDownCa() {
        CmpCaMock.stopSingleCaMock();
    }

    protected TrustChainAndPrivateKey getEnrollmentCredentials() {
        return enrollmentCredentials;
    }
}
