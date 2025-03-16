/*
 * Copyright (c) 2023 Siemens AG
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.siemens.pki.lightweightcmpra.test;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.Before;
import org.junit.Test;

public class TestInventoryLocalPlugin extends InventoryOnlineEnrollmentTestcaseBase {

    @Before
    public void setUp() throws Exception {
        initTestbed("http://localhost:6060/inventoryra", "EnrollmentConfigWithLocalInventory.yaml");
    }

    /**
     * Request rejected by local inventory
     *
     * @throws Exception
     */
    @Test
    public void testLocalInventoryRejection() throws Exception {
        executeCrmfCertificateRequestWithLocalInventory(
                "CN=Subject",
                PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP,
                InventoryResult.REJECTED,
                getEeSignaturebasedProtectionProvider(),
                getEeCmpClient());
    }

    @Test
    public void testLocalInventoryValidation() throws Exception {
        executeCrmfCertificateRequestWithLocalInventory(
                "CN=subject.domain.name",
                PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP,
                InventoryResult.GRANTED,
                getEeSignaturebasedProtectionProvider(),
                getEeCmpClient());
    }

/*    @Test
    public void testLocalInventoryInvocation() {
    }

    @After
    public void tearDown() throws Exception {

    }*/
}