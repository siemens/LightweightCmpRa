/*
 *  Copyright (c) 2021 Siemens AG
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

import com.siemens.pki.lightweightcmpra.test.framework.BaseCredentialService;
import com.siemens.pki.lightweightcmpra.test.framework.CmsDecryptor;
import com.siemens.pki.lightweightcmpra.test.framework.TestUtils;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.Before;
import org.junit.Test;

public class TestCentralKeyGenerationWithKeyTransport extends CkgOnlineEnrollmentTestcaseBase {

    private CmsDecryptor keyTransportDecryptor;

    @Before
    public void setUp() throws Exception {
        final BaseCredentialService eeRsaCredentials =
                new BaseCredentialService("credentials/CMP_EE_Keystore_RSA.p12", TestUtils.getPasswordAsCharArray());
        keyTransportDecryptor =
                new CmsDecryptor(eeRsaCredentials.getEndCertificate(), eeRsaCredentials.getPrivateKey(), null);
        initTestbed("http://localhost:6010/ckgtrans", "EnrollmentConfigWithCKGTrans.yaml");
    }

    @Test
    public void testCrWithKeyTransport() throws Exception {
        executeCrmfCertificateRequestWithoutKey(
                PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP,
                TestUtils.createSignatureBasedProtection(
                        "credentials/CMP_EE_Keystore_RSA.p12", TestUtils.getPasswordAsCharArray()),
                getEeCmpClient(),
                keyTransportDecryptor,
                verifier);
    }
}
