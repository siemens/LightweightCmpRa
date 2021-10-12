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

import static org.junit.Assert.assertEquals;

import java.io.File;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

public class TestRrWithPolling extends DelayedEnrollmentTescaseBase {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(TestRrWithPolling.class);

    @Before
    public void setUp() throws Exception {
        new File("./target/CmpTest/Downstream").mkdirs();
        new File("./target/CmpTest/Upstream").mkdirs();
        initTestbed("DelayedEnrollmentTestConfig.xml",
                "http://localhost:6003/delayedlra");
    }

    @After
    public void shutDown() throws Exception {
        DelayedDeliveryTestcaseBase
                .deleteDirectory(new File("./target/CmpTest/Downstream"));
        DelayedDeliveryTestcaseBase
                .deleteDirectory(new File("./target/CmpTest/Upstream"));
    }

    /**
     * 5.2. Revoking a certificate
     *
     * @throws Exception
     */
    @Test
    public void testRrWithPolling() throws Exception {
        final EnrollmentResult certificateToRevoke =
                executeDelayedCertificateRequest(PKIBody.TYPE_CERT_REQ,
                        PKIBody.TYPE_CERT_REP,
                        getEeSignaturebasedProtectionProvider(),
                        getEeSignatureBasedCmpClient());
        final PKIMessage rr = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest(),
                getEeSignaturebasedProtectionProvider(), PkiMessageGenerator
                        .generateRrBody(certificateToRevoke.certificate));
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(rr));
        }

        final PKIMessage rrResponse = DelayedDeliveryTestcaseBase
                .executeRequestWithPolling(PKIBody.TYPE_ERROR,
                        getEeSignaturebasedProtectionProvider(),
                        getEeSignatureBasedCmpClient(), rr);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(rrResponse));
        }
        assertEquals("message type", PKIBody.TYPE_REVOCATION_REP,
                rrResponse.getBody().getType());

    }
}
