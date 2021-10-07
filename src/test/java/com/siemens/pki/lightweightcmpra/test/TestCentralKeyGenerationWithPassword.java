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
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.PasswordRecipient.PRF;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.siemens.pki.lightweightcmpra.cryptoservices.CmsDecryptor;
import com.siemens.pki.lightweightcmpra.cryptoservices.PasswordEncryptor;
import com.siemens.pki.lightweightcmpra.protection.PasswordBasedMacProtection;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

@RunWith(Parameterized.class)
public class TestCentralKeyGenerationWithPassword
        extends CkgOnlineEnrollmentTestcaseBase {

    public static Object[][] inputList = new Object[][] {
            //
            {PasswordEncryptor.DEFAULT_PRF,
                    PasswordEncryptor.DEFAULT_ITERATIONCOUNT,
                    PasswordEncryptor.DEFAULT_KEK_ALG},
            //
            {PRF.HMacSHA1, PasswordEncryptor.DEFAULT_ITERATIONCOUNT,
                    PasswordEncryptor.DEFAULT_KEK_ALG},
            //
            {PRF.HMacSHA224, PasswordEncryptor.DEFAULT_ITERATIONCOUNT,
                    PasswordEncryptor.DEFAULT_KEK_ALG},
            //
            {PRF.HMacSHA256, PasswordEncryptor.DEFAULT_ITERATIONCOUNT,
                    PasswordEncryptor.DEFAULT_KEK_ALG},
            //
            {PRF.HMacSHA384, PasswordEncryptor.DEFAULT_ITERATIONCOUNT,
                    PasswordEncryptor.DEFAULT_KEK_ALG},
            //
            {PRF.HMacSHA512, PasswordEncryptor.DEFAULT_ITERATIONCOUNT,
                    PasswordEncryptor.DEFAULT_KEK_ALG},
            //
            {PasswordEncryptor.DEFAULT_PRF, 1,
                    PasswordEncryptor.DEFAULT_KEK_ALG},
            //
            {PasswordEncryptor.DEFAULT_PRF, 1000000,
                    PasswordEncryptor.DEFAULT_KEK_ALG},
            //
            {PasswordEncryptor.DEFAULT_PRF,
                    PasswordEncryptor.DEFAULT_ITERATIONCOUNT,
                    CMSAlgorithm.AES128_CBC},
            //
            {PasswordEncryptor.DEFAULT_PRF,
                    PasswordEncryptor.DEFAULT_ITERATIONCOUNT,
                    CMSAlgorithm.AES192_CBC},
            //
            {PasswordEncryptor.DEFAULT_PRF,
                    PasswordEncryptor.DEFAULT_ITERATIONCOUNT,
                    CMSAlgorithm.AES256_CBC},
            //
    };

    @Parameters(name = "{index}: prf=>{0}, iterationCount=>{1}, kek={2}")
    public static List<Object[]> data() {
        final List<Object[]> ret = new ArrayList<>(inputList.length);
        for (final Object[] aktInput : inputList) {
            final PRF prf = (PRF) aktInput[0];
            final Object iterationCount = aktInput[1];
            final Object kek = aktInput[2];
            ret.add(new Object[] {prf.getName(),
                    ((Integer) iterationCount).toString(),
                    MessageDumper
                            .getOidDescriptionForOid((ASN1ObjectIdentifier) kek)
                            .toString(),
                    prf, iterationCount, kek});
        }
        return ret;
    }

    public TestCentralKeyGenerationWithPassword(final String prfAsString,
            final String iterationCountAsString,
            final String kekAlgorithmOIDAsString, final PRF prf,
            final int iterationCount,
            final ASN1ObjectIdentifier kekAlgorithmOID) {
        PasswordEncryptor.setPrf(prf);
        PasswordEncryptor.setKekAlgorithmOID(kekAlgorithmOID);
        PasswordEncryptor.setIterationCount(iterationCount);
    }

    @Test
    public void testCrWithPassword() throws Exception {
        final ProtectionProvider macBasedProvider =
                new PasswordBasedMacProtection("keyIdentification",
                        "myPresharedSecret", 6, 1234,
                        PasswordBasedMacProtection.DEFAULT_OWF_OID,
                        PasswordBasedMacProtection.DEFAULT_MAC_OID);
        executeCrmfCertificateRequestWithoutKey(PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP, macBasedProvider,
                TestUtils.createCmpClient("http://localhost:6012/ckgwithmac"),
                new CmsDecryptor(null, null, "myPresharedSecret".toCharArray()),
                verifier);
    }

}
