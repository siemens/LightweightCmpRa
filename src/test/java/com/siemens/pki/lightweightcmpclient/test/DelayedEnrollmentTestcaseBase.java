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

import com.siemens.pki.lightweightcmpra.test.framework.TestUtils;
import java.io.File;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class DelayedEnrollmentTestcaseBase extends EnrollmentTestcaseBase {
    @Before
    public void setUp() throws Exception {
        super.setUp();
        new File("./target/CmpTest/Downstream").mkdirs();
        new File("./target/CmpTest/Upstream").mkdirs();
        initTestbed("DelayedEnrollmentRaTestConfig.yaml", "DelayedEnrollmentLraTestConfig.yaml");
    }

    @After
    public void shutDown() throws Exception {
        TestUtils.deleteDirectory(new File("./target/CmpTest/Downstream"));
        TestUtils.deleteDirectory(new File("./target/CmpTest/Upstream"));
        super.shutDown();
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
