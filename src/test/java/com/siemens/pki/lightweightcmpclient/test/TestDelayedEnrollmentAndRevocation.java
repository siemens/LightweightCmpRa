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

import static org.junit.Assert.assertTrue;

import com.siemens.pki.lightweightcmpra.main.RA;
import com.siemens.pki.lightweightcmpra.test.framework.TestUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestDelayedEnrollmentAndRevocation extends EnrollmentTestcaseBase {

    private static final String UPSTREAM_DIR = "./target/CmpTest/Upstream_REV";
    private static final String DOWNSTREAM_DIR = "./target/CmpTest/Downstream_REV";

    @BeforeClass
    public static void setupRas() throws Exception {
        TestUtils.createDirectories(DOWNSTREAM_DIR, UPSTREAM_DIR);
        initTestbed("DelayedEnrollmentRaTestConfig.yaml", "DelayedEnrollmentLraTestConfig.yaml");
    }

    @AfterClass
    public static void stopAllRas() {
        RA.stopAllRas();
        TestUtils.removeDirectories(DOWNSTREAM_DIR, UPSTREAM_DIR);
    }

    @After
    public void cleanUpDelayedEnrollmentDirs() {
        TestUtils.deleteAllFilesIn(DOWNSTREAM_DIR, UPSTREAM_DIR);
    }

    @Before
    public void setUpDelayedEnrollmentDirs() {
        TestUtils.deleteAllFilesIn(DOWNSTREAM_DIR, UPSTREAM_DIR);
    }

    @Test(timeout = 100000L)
    public void testCrWithPolling() {
        assertTrue(enrollWithConfig("DelayedClientEnrollmentConfigWithHttpAndSignature.yaml"));
    }

    @Test(timeout = 100000L)
    public void testRrWithPolling() {
        assertTrue(revokeWithConfigAndCert("DelayedClientEnrollmentConfigWithHttpAndSignature.yaml"));
    }
}
