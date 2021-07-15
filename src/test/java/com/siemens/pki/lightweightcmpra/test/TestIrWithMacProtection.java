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

import java.util.function.Function;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.Test;

import com.siemens.pki.lightweightcmpra.protection.PasswordBasedMacProtection;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;

public class TestIrWithMacProtection extends OnlineEnrollmentHttpTestcaseBase {

    /**
     * 5.1.4. Request a certificate from a PKI with MAC protection
     *
     * @throws Exception
     */
    @Test
    public void testIrWithMacProtection() throws Exception {
        final ProtectionProvider macBasedProvider =
                new PasswordBasedMacProtection("myPresharedSecret",
                        "keyIdentification", 1234,
                        new byte[] {6, 5, 4, 3, 2, 1},
                        PasswordBasedMacProtection.DEFAULT_OWF_OID,
                        PasswordBasedMacProtection.DEFAULT_MAC_OID);
        final Function<PKIMessage, PKIMessage> cmpClient = TestUtils
                .createCmpClient("http://localhost:6002/lrawithmacprotection");
        executeCrmfCertificateRequest(PKIBody.TYPE_INIT_REQ,
                PKIBody.TYPE_INIT_REP, macBasedProvider, cmpClient);
    }

}
