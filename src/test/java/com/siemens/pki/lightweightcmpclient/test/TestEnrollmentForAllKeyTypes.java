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
package com.siemens.pki.lightweightcmpclient.test;

import com.siemens.pki.lightweightcmpra.main.RA;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class TestEnrollmentForAllKeyTypes extends EnrollmentTestcaseBase {

    @Parameters(name = "{0}")
    public static Iterable<Object[]> data() throws GeneralSecurityException {
        return Arrays.asList(new Object[][] {
            //
            {"ML-KEM-512"},
            {"ML-KEM-1024"},
            //
            {"ML-DSA-44"},
            {"SLH-DSA-SHA2-128S"},
            {"RSA1024"},
            {"RSA2048"},
            {"Ed448"},
            {"Ed25519"},
            {"secp256r1"},
            //
        });
    }

    @BeforeClass
    public static void setUpRas() throws Exception {
        initTestbed("EnrollmentConfigWithHttpAndSignature.yaml");
    }

    @AfterClass
    public static void stopAllRas() {
        RA.stopAllRas();
    }

    private final String certProfile;

    /**
     * certificate from a trusted PKI with signature protection
     *
     * @throws Exception
     */
    @Test
    public void testCr() throws Exception {
        enrollWithConfigAndCertProfile("ClientEnrollmentConfigWithDifferentKeys.yaml", certProfile);
    }

    public TestEnrollmentForAllKeyTypes(String certProfile) {
        this.certProfile = certProfile;
    }
}
