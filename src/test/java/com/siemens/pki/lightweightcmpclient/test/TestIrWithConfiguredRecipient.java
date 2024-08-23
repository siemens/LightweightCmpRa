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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.siemens.pki.lightweightcmpra.main.RA;
import com.siemens.pki.lightweightcmpra.test.framework.CmpCaMock;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestIrWithConfiguredRecipient extends EnrollmentTestcaseBase {

    @BeforeClass
    public static void setUpRas() throws Exception {
        initTestbed("EnrollmentConfigWithRecipient.yaml");
    }

    @AfterClass
    public static void stopAllRas() {
        RA.stopAllRas();
    }

    @Test
    public void testIrWithNewRecipient() {
        assertTrue(enrollWithConfig("ClientEnrollmentConfigWithHttpAndPBMAC1.yaml"));
        final PKIMessage ir = CmpCaMock.getReceivedRequestAt(1);
        assertEquals(
                "Recipient",
                new GeneralName(new X500Name("CN=newRecipient")),
                ir.getHeader().getRecipient());
    }
}
