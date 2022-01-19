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

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.siemens.pki.lightweightcmpra.cryptoservices.BaseCredentialService;
import com.siemens.pki.lightweightcmpra.cryptoservices.CmsDecryptor;
import com.siemens.pki.lightweightcmpra.cryptoservices.KeyAgreementEncryptor;
import com.siemens.pki.lightweightcmpra.protection.SignatureBasedProtection;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

@RunWith(Parameterized.class)
public class TestCentralKeyGenerationWithKeyAgreement
        extends CkgOnlineEnrollmentTestcaseBase {

    public static Object[][] inputList = new Object[][] {
            //
            {KeyAgreementEncryptor.DEFAULT_KEY_AGREEMENT,
                    KeyAgreementEncryptor.DEFAULT_KEY_ENCRYPTION},
            //
            {KeyAgreementEncryptor.DEFAULT_KEY_AGREEMENT,
                    new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.5")},
            //
            {KeyAgreementEncryptor.DEFAULT_KEY_AGREEMENT,
                    new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.25")},
            //
            {KeyAgreementEncryptor.DEFAULT_KEY_AGREEMENT,
                    new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.45")},
            //
            //
            {new ASN1ObjectIdentifier("1.3.132.1.11.0"),
                    KeyAgreementEncryptor.DEFAULT_KEY_ENCRYPTION},
            //
            {new ASN1ObjectIdentifier("1.3.132.1.11.1"),
                    KeyAgreementEncryptor.DEFAULT_KEY_ENCRYPTION},
            //
            {new ASN1ObjectIdentifier("1.3.132.1.11.2"),
                    KeyAgreementEncryptor.DEFAULT_KEY_ENCRYPTION},
            //
            {new ASN1ObjectIdentifier("1.3.132.1.11.3"),
                    KeyAgreementEncryptor.DEFAULT_KEY_ENCRYPTION},
            //
            //
            {new ASN1ObjectIdentifier("1.3.132.1.14.0"),
                    KeyAgreementEncryptor.DEFAULT_KEY_ENCRYPTION},
            //
            {new ASN1ObjectIdentifier("1.3.132.1.14.1"),
                    KeyAgreementEncryptor.DEFAULT_KEY_ENCRYPTION},
            //
            {new ASN1ObjectIdentifier("1.3.132.1.14.2"),
                    KeyAgreementEncryptor.DEFAULT_KEY_ENCRYPTION},
            //
            {new ASN1ObjectIdentifier("1.3.132.1.14.3"),
                    KeyAgreementEncryptor.DEFAULT_KEY_ENCRYPTION},
            //
            //
            {new ASN1ObjectIdentifier("1.3.132.1.15.0"),
                    KeyAgreementEncryptor.DEFAULT_KEY_ENCRYPTION},
            //
            {new ASN1ObjectIdentifier("1.3.132.1.15.1"),
                    KeyAgreementEncryptor.DEFAULT_KEY_ENCRYPTION},
            //
            {new ASN1ObjectIdentifier("1.3.132.1.15.2"),
                    KeyAgreementEncryptor.DEFAULT_KEY_ENCRYPTION},
            //
            {new ASN1ObjectIdentifier("1.3.132.1.15.3"),
                    KeyAgreementEncryptor.DEFAULT_KEY_ENCRYPTION},
            //
            //
    };

    @Parameters(name = "{index}: keyAgreement=>{0}, keyEncryption=>{1}")
    public static List<Object[]> data() {
        final List<Object[]> ret = new ArrayList<>(inputList.length);
        for (final Object[] aktInput : inputList) {
            final Object keyAgreement = aktInput[0];
            final Object keyEncryption = aktInput[1];
            ret.add(new Object[] {
                    MessageDumper
                            .getOidDescriptionForOid(
                                    (ASN1ObjectIdentifier) keyAgreement)
                            .toString(),
                    MessageDumper
                            .getOidDescriptionForOid(
                                    (ASN1ObjectIdentifier) keyEncryption)
                            .toString(),
                    keyAgreement, keyEncryption});
        }
        return ret;
    }

    private CmsDecryptor keyAgreementDecryptor;

    public TestCentralKeyGenerationWithKeyAgreement(
            final String keyAgreementAsString,
            final String keyEncryptionAsString,
            final ASN1ObjectIdentifier keyAgreementOID,
            final ASN1ObjectIdentifier keyEncryptionOID) {
        KeyAgreementEncryptor.setKeyAgreementOID(keyAgreementOID);
        KeyAgreementEncryptor.setKeyEncryptionOID(keyEncryptionOID);
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
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
                PKIBody.TYPE_CERT_REP,
                new SignatureBasedProtection("credentials/CMP_EE_Keystore.p12",
                        TestUtils.PASSWORD_AS_CHAR_ARRAY),
                TestUtils.createCmpClient("http://localhost:6011/ckgagree"),
                keyAgreementDecryptor, verifier);
    }
}
