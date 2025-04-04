/*
 * Copyright (c) 2023 Siemens AG
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.siemens.pki.lightweightcmpra.test;

import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import com.siemens.pki.lightweightcmpra.test.framework.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.KeyPair;
import java.util.function.Function;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class InventoryOnlineEnrollmentTestcaseBase extends OnlineEnrollmentTestcaseBase {
    private static final Logger LOGGER = LoggerFactory.getLogger(InventoryOnlineEnrollmentTestcaseBase.class);

    public enum InventoryResult {
        GRANTED,
        REJECTED
    }

    private static InventoryResult isGranted(final PKIMessage msg) {
        final PKIBody body = msg.getBody();
        switch (body.getType()) {
            case PKIBody.TYPE_CERT_REP:
            case PKIBody.TYPE_INIT_REP:
            case PKIBody.TYPE_KEY_UPDATE_REP: {
                final CertResponse[] responses = ((CertRepMessage) body.getContent()).getResponse();
                if (responses != null && responses.length == 1 && responses[0].getStatus() != null) {
                    switch (responses[0].getStatus().getStatus().intValue()) {
                        case PKIStatus.GRANTED:
                        case PKIStatus.GRANTED_WITH_MODS:
                        case PKIStatus.WAITING:
                            return InventoryResult.GRANTED;
                    }
                    return InventoryResult.REJECTED;
                }
                return InventoryResult.GRANTED;
            }
            case PKIBody.TYPE_CERT_CONFIRM: {
                final CertStatus[] responses = ((CertConfirmContent) body.getContent()).toCertStatusArray();
                if (responses != null && responses.length == 1 && responses[0].getStatusInfo() != null) {
                    switch (responses[0].getStatusInfo().getStatus().intValue()) {
                        case PKIStatus.GRANTED:
                        case PKIStatus.GRANTED_WITH_MODS:
                            return InventoryResult.GRANTED;
                    }
                    return InventoryResult.REJECTED;
                }
                return InventoryResult.GRANTED;
            }
            case PKIBody.TYPE_ERROR:
                return InventoryResult.REJECTED;
        }
        return InventoryResult.REJECTED;
    }

    public static void executeCrmfCertificateRequestWithLocalInventory(
            final String subjectName,
            final int requestMessageType,
            final int expectedResponseMessageType,
            final InventoryResult expectedInventoryValidationResult,
            final ProtectionProvider protectionProvider,
            final Function<PKIMessage, PKIMessage> cmpClient)
            throws Exception {
        final KeyPair keyPair = getKeyGenerator().generateKeyPair();
        final CertTemplateBuilder ctb = new CertTemplateBuilder()
                .setPublicKey(
                        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()))
                .setSubject(new X500Name(subjectName));

        final PKIBody crBody =
                PkiMessageGenerator.generateIrCrKurBody(requestMessageType, ctb.build(), null, keyPair.getPrivate());

        final PKIMessage cr =
                PkiMessageGenerator.generateAndProtectMessage(new HeaderProviderForTest(), protectionProvider, crBody);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(cr));
        }
        final PKIMessage crResponse = cmpClient.apply(cr);

        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(crResponse));
        }
        assertEquals(
                "message type",
                expectedResponseMessageType,
                crResponse.getBody().getType());

        assertEquals(
                "inventory validation result",
                expectedInventoryValidationResult,
                isGranted(crResponse));

        if (expectedInventoryValidationResult == InventoryResult.GRANTED) {

            final CMPCertificate enrolledCertificate = ((CertRepMessage)
                    crResponse.getBody().getContent())
                    .getResponse()[0]
                    .getCertifiedKeyPair()
                    .getCertOrEncCert()
                    .getCertificate();

            final PKIMessage certConf = PkiMessageGenerator.generateAndProtectMessage(
                    new HeaderProviderForTest(crResponse.getHeader()),
                    protectionProvider,
                    PkiMessageGenerator.generateCertConfBody(enrolledCertificate));

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(certConf));
            }
            final PKIMessage pkiConf = cmpClient.apply(certConf);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(pkiConf));
            }
            assertEquals("message type", PKIBody.TYPE_CONFIRM, pkiConf.getBody().getType());
        }
    }

    public static void executeCrmfCertificateRequestWithExternalInventory(
            final int requestMessageType,
            final int expectedResponseMessageType,
            final ProtectionProvider protectionProvider,
            final Function<PKIMessage, PKIMessage> cmpClient,
            InventoryResult expectedInventoryValidationResult)
            throws Exception {
        final KeyPair keyPair = getKeyGenerator().generateKeyPair();
        final CertTemplateBuilder ctb = new CertTemplateBuilder()
                .setPublicKey(
                        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()))
                .setSubject(new X500Name("CN=Subject"));

        final PKIBody crBody =
                PkiMessageGenerator.generateIrCrKurBody(requestMessageType, ctb.build(), null, keyPair.getPrivate());

        final PKIMessage cr =
                PkiMessageGenerator.generateAndProtectMessage(new HeaderProviderForTest(), protectionProvider, crBody);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(cr));
        }
        final PKIMessage crResponse = cmpClient.apply(cr);

        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(crResponse));
        }
        assertEquals(
                "message type",
                expectedResponseMessageType,
                crResponse.getBody().getType());

        //assertTrue("external inventory invoked", new File("C:\\path\\to\\AppData\\Local\\Temp\\RaPluginLog.txt").length() > 0);

        assertEquals(
                "inventory validation result",
                expectedInventoryValidationResult,
                isGranted(crResponse));

        if (expectedInventoryValidationResult == InventoryResult.GRANTED) {

            final CMPCertificate enrolledCertificate = ((CertRepMessage)
                    crResponse.getBody().getContent())
                    .getResponse()[0]
                    .getCertifiedKeyPair()
                    .getCertOrEncCert()
                    .getCertificate();

            final PKIMessage certConf = PkiMessageGenerator.generateAndProtectMessage(
                    new HeaderProviderForTest(crResponse.getHeader()),
                    protectionProvider,
                    PkiMessageGenerator.generateCertConfBody(enrolledCertificate));

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(certConf));
            }
            final PKIMessage pkiConf = cmpClient.apply(certConf);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(pkiConf));
            }
            assertEquals("message type", PKIBody.TYPE_CONFIRM, pkiConf.getBody().getType());
        }
    }

    public static void executeCrmfCertificateRequestWithDslInventory(
            final int requestMessageType,
            final int expectedResponseMessageType,
            final ProtectionProvider protectionProvider,
            final Function<PKIMessage, PKIMessage> cmpClient, InventoryResult expectedInventoryValidationResult)
            throws Exception {
        final KeyPair keyPair = getKeyGenerator().generateKeyPair();
        final CertTemplateBuilder ctb = new CertTemplateBuilder()
                .setPublicKey(
                        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()))
                .setSubject(new X500Name("C=DE, O=Siemens, CN=subject.siemens.com"));

        final PKIBody crBody =
                PkiMessageGenerator.generateIrCrKurBody(requestMessageType, ctb.build(), null, keyPair.getPrivate());

        final PKIMessage cr =
                PkiMessageGenerator.generateAndProtectMessage(new HeaderProviderForTest(), protectionProvider, crBody);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(cr));
        }
        final PKIMessage crResponse = cmpClient.apply(cr);

        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(crResponse));
        }
        assertEquals(
                "message type",
                expectedResponseMessageType,
                crResponse.getBody().getType());

        //assertTrue("external inventory invoked", new File("C:\\path\\to\\AppData\\Local\\Temp\\RaPluginLog.txt").length() > 0);

        assertEquals(
                "inventory validation result",
                expectedInventoryValidationResult,
                isGranted(crResponse));

        if (expectedInventoryValidationResult == InventoryResult.GRANTED) {

            final CMPCertificate enrolledCertificate = ((CertRepMessage)
                    crResponse.getBody().getContent())
                    .getResponse()[0]
                    .getCertifiedKeyPair()
                    .getCertOrEncCert()
                    .getCertificate();

            final PKIMessage certConf = PkiMessageGenerator.generateAndProtectMessage(
                    new HeaderProviderForTest(crResponse.getHeader()),
                    protectionProvider,
                    PkiMessageGenerator.generateCertConfBody(enrolledCertificate));

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(certConf));
            }
            final PKIMessage pkiConf = cmpClient.apply(certConf);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(pkiConf));
            }
            assertEquals("message type", PKIBody.TYPE_CONFIRM, pkiConf.getBody().getType());
        }
    }
}
