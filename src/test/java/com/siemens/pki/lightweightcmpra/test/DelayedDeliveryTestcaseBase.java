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
import java.util.function.Function;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import com.siemens.pki.lightweightcmpra.test.framework.HeaderProviderForTest;

public class DelayedDeliveryTestcaseBase {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(DelayedDeliveryTestcaseBase.class);

    public static boolean deleteDirectory(final File directoryToBeDeleted) {
        final File[] allContents = directoryToBeDeleted.listFiles();
        if (allContents != null) {
            for (final File file : allContents) {
                deleteDirectory(file);
            }
        }
        return directoryToBeDeleted.delete();
    }

    protected static PKIMessage executeRequestWithPolling(
            final int expectedWaitingResponseMessageType,
            final ProtectionProvider protectionProvider,
            final Function<PKIMessage, PKIMessage> cmpClient,
            final PKIMessage request) throws Exception, InterruptedException {
        PKIMessage response = cmpClient.apply(request);

        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't enabled
            LOGGER.debug("test client got:\n"
                    + MessageDumper.dumpPkiMessage(response));
        }
        final int responseType = response.getBody().getType();
        assertEquals("message type", expectedWaitingResponseMessageType,
                responseType);

        boolean pollingTriggered = false;
        switch (responseType) {
        case PKIBody.TYPE_INIT_REP:
        case PKIBody.TYPE_CERT_REP:
        case PKIBody.TYPE_KEY_UPDATE_REP: {
            final CertResponse certResponseInBody =
                    ((CertRepMessage) response.getBody().getContent())
                            .getResponse()[0];
            if (certResponseInBody.getStatus() != null && certResponseInBody
                    .getStatus().getStatus().intValue() == PKIStatus.WAITING) {
                pollingTriggered = true;
            }
            break;
        }
        case PKIBody.TYPE_ERROR: {
            final ErrorMsgContent errorContent =
                    (ErrorMsgContent) response.getBody().getContent();
            if (errorContent.getPKIStatusInfo().getStatus()
                    .intValue() == PKIStatus.WAITING) {
                pollingTriggered = true;
            }
            break;
        }
        default:
            ;
        }
        if (pollingTriggered) {
            // delayed delivery triggered, start polling
            for (;;) {
                final PKIMessage pollReq =
                        PkiMessageGenerator.generateAndProtectMessage(
                                new HeaderProviderForTest(response.getHeader()),
                                protectionProvider,
                                PkiMessageGenerator.generatePollReq());
                response = cmpClient.apply(pollReq);
                if (response.getBody().getType() != PKIBody.TYPE_POLL_REP) {
                    break;
                }
                final ASN1Integer checkAfter =
                        ((PollRepContent) response.getBody().getContent())
                                .getCheckAfter(0);
                Thread.sleep(1000L * checkAfter.getValue().longValue());
            }
        }
        return response;
    }

}
