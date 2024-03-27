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
package com.siemens.pki.lightweightcmpclient.test;

import com.siemens.pki.lightweightcmpra.main.RA;
import com.siemens.pki.lightweightcmpra.test.framework.TestUtils;
import java.security.GeneralSecurityException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class DelayedEnrollmentTestcaseBase extends EnrollmentTestcaseBase {

    @BeforeClass
    public static void setupRas() throws GeneralSecurityException, InterruptedException, Exception {
        TestUtils.createDirectories("./target/CmpTest/Downstream", "./target/CmpTest/Upstream");
        initTestbed("DelayedEnrollmentRaTestConfig.yaml", "DelayedEnrollmentLraTestConfig.yaml");
    }

    @AfterClass
    public static void stopAllRas() {
        RA.stopAllRas();
        TestUtils.removeDirectories("./target/CmpTest/Downstream", "./target/CmpTest/Upstream");
    }

    @After
    public void cleanUpDelayedEnrollmentDirs() {}

    @Before
    public void setUpDelayedEnrollmentDirs() throws Exception {
        TestUtils.deleteAllFilesIn("./target/CmpTest/Downstream", "./target/CmpTest/Upstream");
    }

    @Test
    public void testCrWithPolling() throws Exception {
        enrollWithConfig("DelayedClientEnrollmentConfigWithHttpAndSignature.yaml");
    }

    @Test
    public void testRrWithPolling() throws Exception {
        revokeWithConfigAndCert("DelayedClientEnrollmentConfigWithHttpAndSignature.yaml");
    }
}
