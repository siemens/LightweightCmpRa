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

import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.Before;
import org.junit.Test;

import com.siemens.pki.lightweightcmpra.test.framework.BaseCredentialService;
import com.siemens.pki.lightweightcmpra.test.framework.CmsDecryptor;
import com.siemens.pki.lightweightcmpra.test.framework.TestUtils;

public class TestCentralKeyGenerationWithKeyAgreement
        extends CkgOnlineEnrollmentTestcaseBase {

    private CmsDecryptor keyAgreementDecryptor;

    @Before
    public void setUp() throws Exception {
        initTestbed("http://localhost:6011/ckgagree",
                "EnrollmentConfigWithCKGAgree.yaml");
        final BaseCredentialService eeCredentials =
                new BaseCredentialService("credentials/CMP_EE_Keystore.p12",
                        TestUtils.getPasswordAsCharArray());
        keyAgreementDecryptor =
                new CmsDecryptor(eeCredentials.getEndCertificate(),
                        eeCredentials.getPrivateKey(), null);
    }

    @Test
    public void testCrWithKeyAgreement() throws Exception {
        executeCrmfCertificateRequestWithoutKey(PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP,
                TestUtils.createSignatureBasedProtection(
                        "credentials/CMP_EE_Keystore.p12",
                        TestUtils.getPasswordAsCharArray()),
                TestUtils.createCmpClient("http://localhost:6011/ckgagree"),
                keyAgreementDecryptor, verifier);
    }
}
