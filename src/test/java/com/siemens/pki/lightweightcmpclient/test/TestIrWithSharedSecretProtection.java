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
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestIrWithSharedSecretProtection extends EnrollmentTestcaseBase {

    @BeforeClass
    public static void setUpRas() throws Exception {
        initTestbed("EnrollmentConfigWithHttpAndPassword.yaml");
    }

    @AfterClass
    public static void stopAllRas() {
        RA.stopAllRas();
    }

    @Test
    public void testIrWithPasswordBasedProtection() throws Exception {
        enrollWithConfig("ClientEnrollmentConfigWithHttpAndPassword.yaml");
    }

    @Test
    public void testIrWithPBMAC1Protection() throws Exception {
        enrollWithConfig("ClientEnrollmentConfigWithHttpAndPBMAC1.yaml");
    }
}
