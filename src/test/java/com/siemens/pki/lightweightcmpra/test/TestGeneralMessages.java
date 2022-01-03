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
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.function.Function;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;
import com.siemens.pki.lightweightcmpra.msgprocessing.RootCaKeyUpdateContent;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

public class TestGeneralMessages extends CmpTestcaseBase {
    private static final Logger LOGGER =
            LoggerFactory.getLogger(TestGeneralMessages.class);

    @Test
    @Ignore("only used for generation of a new CertReqTemplateContent")
    public void generateCertReqTemplateContent() throws IOException {
        try (FileOutputStream out =
                new FileOutputStream(new File(CmpTestcaseBase.CONFIG_DIRECTORY,
                        "credentials/CertTemplate.der"))) {
            final CertTemplateBuilder ctb = new CertTemplateBuilder();
            ctb.setSubject(new X500Name("CN=test"));
            final Controls controls = new Controls(new AttributeTypeAndValue(
                    new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.1.11"),
                    new ASN1Integer(2048)));
            final ASN1Sequence certReqTemplateContent = new DERSequence(
                    new ASN1Encodable[] {ctb.build(), controls});
            out.write(certReqTemplateContent.getEncoded(ASN1Encoding.DER));
        }

    }

    @Before
    public void setUp() throws Exception {
        initTestbed("SupportMessagesTestConfig.xml",
                "http://localhost:6004/supportlra");
    }

    /*
     * 4.4.2. Get CA certificates
     */
    @Test
    public void testGetCaCerts() throws Exception {
        final Function<PKIMessage, PKIMessage> eeCmpClient =
                getEeSignatureBasedCmpClient();
        final ASN1ObjectIdentifier getCaCertOid =
                new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.17");
        final PKIBody genmBody = new PKIBody(PKIBody.TYPE_GEN_MSG,
                new GenMsgContent(new InfoTypeAndValue(getCaCertOid)));
        final PKIMessage genm = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest(),
                getEeSignaturebasedProtectionProvider(), genmBody);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't enabled
            LOGGER.debug("send" + MessageDumper.dumpPkiMessage(genm));
        }
        final PKIMessage genr = eeCmpClient.apply(genm);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't enabled
            LOGGER.debug("got" + MessageDumper.dumpPkiMessage(genr));
        }
        assertEquals("message type", PKIBody.TYPE_GEN_REP,
                genr.getBody().getType());
        final GenRepContent content =
                (GenRepContent) genr.getBody().getContent();
        final InfoTypeAndValue[] itav = content.toInfoTypeAndValueArray();
        assertEquals("number of itavs", 1, itav.length);
        assertEquals("getCaCertOid", getCaCertOid, itav[0].getInfoType());
        //        id-it-caCerts OBJECT IDENTIFIER ::= {1 3 6 1 5 5 7 4 17}
        //        CaCerts ::= SEQUENCE OF CMPCertificate
        //        }
        final ASN1Sequence value = (ASN1Sequence) itav[0].getInfoValue();
        assertEquals("number of returned certificates", 20, value.size());
    }

    /*
     * 4.4.4. Get certificate request template
     */
    @Test
    public void testGetCertificateRequestTemplate() throws Exception {
        final Function<PKIMessage, PKIMessage> eeCmpClient =
                getEeSignatureBasedCmpClient();
        final ASN1ObjectIdentifier getCaCertOid =
                new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.19");
        final PKIBody genmBody = new PKIBody(PKIBody.TYPE_GEN_MSG,
                new GenMsgContent(new InfoTypeAndValue(getCaCertOid)));
        final PKIMessage genm = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest(),
                getEeSignaturebasedProtectionProvider(), genmBody);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't enabled
            LOGGER.debug("send" + MessageDumper.dumpPkiMessage(genm));
        }
        final PKIMessage genr = eeCmpClient.apply(genm);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("got" + MessageDumper.dumpPkiMessage(genr));
        }
        assertEquals("message type", PKIBody.TYPE_GEN_REP,
                genr.getBody().getType());
        final GenRepContent content =
                (GenRepContent) genr.getBody().getContent();
        final InfoTypeAndValue[] itav = content.toInfoTypeAndValueArray();
        assertEquals("number of itavs", 1, itav.length);
        assertEquals("getCaCertOid", getCaCertOid, itav[0].getInfoType());
        //CertReqTemplateContent ::= SEQUENCE {
        //    certTemplate           CertTemplate,
        //    -- prefilled certTemplate structure elements
        //    -- The SubjectPublicKeyInfo field in the certTemplate MUST NOT
        //    -- be used.
        //    controls               Controls OPTIONAL
        //    -- MAY be used to specify supported algorithms.
        //    -- Controls  ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue
        //    -- as specified in CRMF (RFC4211)
        //    }
        final ASN1Sequence value = (ASN1Sequence) itav[0].getInfoValue();
        assertNotNull("parse CertTemplate",
                CertTemplate.getInstance(value.getObjectAt(0)));
        final ASN1Encodable optionalControls = value.getObjectAt(1);
        final AttributeTypeAndValue[] controls = Controls
                .getInstance(optionalControls).toAttributeTypeAndValueArray();

        assertEquals(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.1.11"),
                controls[0].getType());

        assertNotNull("parse INTEGER",
                ASN1Integer.getInstance(controls[0].getValue()));
    }

    /*
     * 4.4.3. Get root CA certificate update
     */
    @Test
    public void testGetRootCaKeyUpdateInfo() throws Exception {
        final Function<PKIMessage, PKIMessage> eeCmpClient =
                getEeSignatureBasedCmpClient();
        final ASN1ObjectIdentifier getCaCertOid =
                new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.18");
        final PKIBody genmBody = new PKIBody(PKIBody.TYPE_GEN_MSG,
                new GenMsgContent(new InfoTypeAndValue(getCaCertOid)));
        final PKIMessage genm = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest(),
                getEeSignaturebasedProtectionProvider(), genmBody);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("send" + MessageDumper.dumpPkiMessage(genm));
        }
        final PKIMessage genr = eeCmpClient.apply(genm);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("got" + MessageDumper.dumpPkiMessage(genr));
        }
        assertEquals("message type", PKIBody.TYPE_GEN_REP,
                genr.getBody().getType());
        final GenRepContent content =
                (GenRepContent) genr.getBody().getContent();
        final InfoTypeAndValue[] itav = content.toInfoTypeAndValueArray();
        assertEquals("number of itavs", 1, itav.length);
        assertEquals("getCaCertOid", getCaCertOid, itav[0].getInfoType());
        //        id-it-rootCaKeyUpdate OBJECT IDENTIFIER ::= {1 3 6 1 5 5 7 4 18}
        //        RootCaKeyUpdate ::= SEQUENCE {
        //            newWithNew       CMPCertificate
        //            newWithOld   [0] CMPCertificate OPTIONAL,
        //            oldWithNew   [1] CMPCertificate OPTIONAL,
        //        }
        final ASN1Sequence value = (ASN1Sequence) itav[0].getInfoValue();
        assertNotNull("parse RootCaKeyUpdateContent",
                RootCaKeyUpdateContent.getInstance(value));
    }
}
