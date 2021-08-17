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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.siemens.pki.lightweightcmpra.protection.PasswordBasedMacProtection;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

@RunWith(Parameterized.class)
public class TestIrWithPasswordBasedMacProtection
        extends OnlineEnrollmentHttpTestcaseBase {

    public static Object[][] inputList = new Object[][] {
            //
            {PasswordBasedMacProtection.DEFAULT_OWF_OID,
                    PasswordBasedMacProtection.DEFAULT_MAC_OID},
            {PasswordBasedMacProtection.DEFAULT_OWF_OID,
                    PKCSObjectIdentifiers.id_hmacWithSHA512},
            {new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
                    PKCSObjectIdentifiers.id_hmacWithSHA224},
            {new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2"),
                    PKCSObjectIdentifiers.id_hmacWithSHA384},
            {new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3"),
                    PKCSObjectIdentifiers.id_hmacWithSHA256},
            {new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.4"),
                    PasswordBasedMacProtection.DEFAULT_MAC_OID},
            {new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
                    PasswordBasedMacProtection.DEFAULT_MAC_OID}

    };
    //

    @Parameters(name = "{index}: owf=>{0}, mac=>{1}")
    public static List<Object[]> data() {
        final List<Object[]> ret = new ArrayList<>(inputList.length);
        for (final Object[] aktInput : inputList) {
            final Object owf = aktInput[0];
            final Object mac = aktInput[1];
            ret.add(new Object[] {
                    MessageDumper
                            .getOidDescriptionForOid((ASN1ObjectIdentifier) owf)
                            .toString(),
                    MessageDumper
                            .getOidDescriptionForOid((ASN1ObjectIdentifier) mac)
                            .toString(),
                    owf, mac});
        }
        return ret;
    }

    private final ASN1ObjectIdentifier owf;

    private final ASN1ObjectIdentifier mac;

    public TestIrWithPasswordBasedMacProtection(final String owfAsString,
            final String macAsString, final ASN1ObjectIdentifier owf,
            final ASN1ObjectIdentifier mac) {
        this.owf = owf;
        this.mac = mac;
    }

    /**
     * 5.1.4. Request a certificate from a PKI with MAC protection
     *
     * @throws Exception
     */
    @Test
    public void testIrWithPasswordBasedMacProtection() throws Exception {
        final ProtectionProvider macBasedProvider =
                new PasswordBasedMacProtection("keyIdentification",
                        "myPresharedSecret", 6, 1234, owf, mac);
        final Function<PKIMessage, PKIMessage> cmpClient = TestUtils
                .createCmpClient("http://localhost:6002/lrawithmacprotection");
        executeCrmfCertificateRequest(PKIBody.TYPE_INIT_REQ,
                PKIBody.TYPE_INIT_REP, macBasedProvider, cmpClient);
    }

}
