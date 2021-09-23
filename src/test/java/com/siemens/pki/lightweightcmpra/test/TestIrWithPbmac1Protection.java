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
import java.util.function.Function;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.siemens.pki.lightweightcmpra.protection.PBMAC1Protection;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

@RunWith(Parameterized.class)
public class TestIrWithPbmac1Protection
        extends OnlineEnrollmentHttpTestcaseBase {

    public static Object[][] inputList = new Object[][] {
            {PBMAC1Protection.DEFAULT_PRF, PBMAC1Protection.DEFAULT_MAC},
            //
            {
                    //
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.id_hmacWithSHA1,
                            DERNull.INSTANCE),
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.id_hmacWithSHA1,
                            DERNull.INSTANCE)},
            //
            {
                    //
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.id_hmacWithSHA224,
                            DERNull.INSTANCE),
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.id_hmacWithSHA224,
                            DERNull.INSTANCE)},
            //
            {
                    //
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.id_hmacWithSHA384,
                            DERNull.INSTANCE),
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.id_hmacWithSHA384,
                            DERNull.INSTANCE)},
            //
            {
                    //
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.id_hmacWithSHA512,
                            DERNull.INSTANCE),
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.id_hmacWithSHA512,
                            DERNull.INSTANCE)},
            {
                    //
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.id_hmacWithSHA1,
                            DERNull.INSTANCE),
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.id_hmacWithSHA512,
                            DERNull.INSTANCE)},
            {
                    //
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.id_hmacWithSHA512,
                            DERNull.INSTANCE),
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.id_hmacWithSHA1,
                            DERNull.INSTANCE)},
            {
                    //
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.id_hmacWithSHA512,
                            DERNull.INSTANCE),
                    new AlgorithmIdentifier(
                            NISTObjectIdentifiers.id_KmacWithSHAKE128,
                            DERNull.INSTANCE)},
            //
            {new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1,
                    DERNull.INSTANCE),
                    new AlgorithmIdentifier(
                            NISTObjectIdentifiers.id_KmacWithSHAKE256,
                            DERNull.INSTANCE)}};

    @Parameters(name = "{index}: prf=>{0}, mac=>{1}")
    public static List<Object[]> data() {
        final List<Object[]> ret = new ArrayList<>(inputList.length);
        for (final Object[] aktInput : inputList) {
            final Object prf = aktInput[0];
            final Object mac = aktInput[1];
            ret.add(new Object[] {
                    MessageDumper.dumpAsn1Object((ASN1Object) prf),
                    MessageDumper.dumpAsn1Object((ASN1Object) mac), prf, mac});
        }
        return ret;
    }

    private final AlgorithmIdentifier prf;

    private final AlgorithmIdentifier mac;

    public TestIrWithPbmac1Protection(final String prfAsString,
            final String macAsString, final AlgorithmIdentifier prf,
            final AlgorithmIdentifier mac) {
        this.prf = prf;
        this.mac = mac;
    }

    /**
     * 5.1.4. Request a certificate from a PKI with PBMAC1 protection
     *
     * @throws Exception
     */
    @Test
    public void testIrWithPbmac1Protection() throws Exception {
        final ProtectionProvider macBasedProvider =
                new PBMAC1Protection("keyIdentification", "myPresharedSecret",
                        16, 1234, 256, prf, mac);
        final Function<PKIMessage, PKIMessage> cmpClient = TestUtils
                .createCmpClient("http://localhost:6002/lrawithmacprotection");
        executeCrmfCertificateRequest(PKIBody.TYPE_INIT_REQ,
                PKIBody.TYPE_INIT_REP, macBasedProvider, cmpClient);
    }

}
