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

import static org.junit.Assert.assertEquals;

import java.util.function.Function;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

public class TestRr extends OnlineEnrollmentHttpTestcaseBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestRr.class);

    /**
     * 5.2. Revoking a certificate
     *
     * @throws Exception
     */
    @Test
    public void testRr() throws Exception {
        final EnrollmentResult certificateToRevoke =
                executeCrmfCertificateRequest(PKIBody.TYPE_CERT_REQ,
                        PKIBody.TYPE_CERT_REP,
                        getEeSignaturebasedProtectionProvider(),
                        getEeSignatureBasedCmpClient());
        final ProtectionProvider rrProtector = getEnrollmentCredentials()
                .setEndEntityToProtect(certificateToRevoke.certificate,
                        certificateToRevoke.privateKey);
        final Function<PKIMessage, PKIMessage> eeRrKurClient =
                TestUtils.createCmpClient("http://localhost:6001/rrkur");
        final PKIMessage rr = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest(), rrProtector, PkiMessageGenerator
                        .generateRrBody(certificateToRevoke.certificate));
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(rr));
        }
        final PKIMessage rrResponse = eeRrKurClient.apply(rr);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(rrResponse));
        }
        assertEquals("message type", PKIBody.TYPE_REVOCATION_REP,
                rrResponse.getBody().getType());

    }

}
