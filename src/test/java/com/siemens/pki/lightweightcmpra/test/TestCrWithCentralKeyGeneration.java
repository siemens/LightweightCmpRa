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

import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.Before;
import org.junit.Test;

import com.siemens.pki.lightweightcmpra.config.xmlparser.TRUSTCREDENTIALS;
import com.siemens.pki.lightweightcmpra.cryptoservices.BaseCredentialService;
import com.siemens.pki.lightweightcmpra.cryptoservices.CmsDecryptor;
import com.siemens.pki.lightweightcmpra.cryptoservices.DataSignVerifier;
import com.siemens.pki.lightweightcmpra.protection.PasswordBasedMacProtection;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;

public class TestCrWithCentralKeyGeneration
        extends OnlineEnrollmentTestcaseBase {
    private CmsDecryptor keyAgreementDecryptor;
    private DataSignVerifier verifier;

    @Before
    public void setUp() throws Exception {

        initTestbed("OnlineEnrollmentTestConfigWithCentralKeyGeneration.xml",
                null);
        final TRUSTCREDENTIALS verifierConfig = new TRUSTCREDENTIALS();
        verifierConfig
                .setTrustStorePath("credentials/CMP_LRA_DOWNSTREAM_Root.pem");
        verifier = new DataSignVerifier(verifierConfig);
        final BaseCredentialService eeCredentials =
                new BaseCredentialService("credentials/CMP_EE_Keystore.p12",
                        TestUtils.PASSWORD_AS_CHAR_ARRAY);
        keyAgreementDecryptor =
                new CmsDecryptor(eeCredentials.getEndCertificate(),
                        eeCredentials.getPrivateKey(), null);
    }

    @Test
    public void testCrWithKeyAgreement() throws Exception {
        executeCrmfCertificateRequestWithoutKey(PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP, getEeSignaturebasedProtectionProvider(),
                TestUtils.createCmpClient("http://localhost:6011/ckgagree"),
                keyAgreementDecryptor, verifier);
    }

    @Test
    public void testCrWithPassword() throws Exception {
        final ProtectionProvider macBasedProvider =
                new PasswordBasedMacProtection("myPresharedSecret",
                        "keyIdentification", 1234,
                        new byte[] {6, 5, 4, 3, 2, 1},
                        PasswordBasedMacProtection.DEFAULT_OWF_OID,
                        PasswordBasedMacProtection.DEFAULT_MAC_OID);
        executeCrmfCertificateRequestWithoutKey(PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP, macBasedProvider,
                TestUtils.createCmpClient("http://localhost:6012/ckgwithmac"),
                new CmsDecryptor(null, null, "myPresharedSecret".toCharArray()),
                verifier);
    }

}
