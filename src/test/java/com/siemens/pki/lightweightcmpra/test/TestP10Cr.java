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

import org.junit.Ignore;
import org.junit.Test;

public class TestP10Cr extends OnlineEnrollmentTestcaseBase {
    /**
     * A certificate from a legacy PKI using PKCS#10 request
     *
     * @throws Exception
     */
    @Test(timeout = 100000L)
    @Ignore("PKCS#10 CSR not supported anymore")
    public void testP10Cr() throws Exception {
        executeP10CertificateRequest(getEeSignaturebasedProtectionProvider(), getEeCmpClient());
    }
}
