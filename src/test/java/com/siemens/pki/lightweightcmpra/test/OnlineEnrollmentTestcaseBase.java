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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.function.Function;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.cryptoservices.CmsDecryptor;
import com.siemens.pki.lightweightcmpra.cryptoservices.DataSignVerifier;
import com.siemens.pki.lightweightcmpra.cryptoservices.DataSigner;
import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

public class OnlineEnrollmentTestcaseBase extends EnrollmentTestcaseBase {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(OnlineEnrollmentTestcaseBase.class);

    static public EnrollmentResult executeCrmfCertificateRequest(
            final int requestMesssageType,
            final int expectedResponseMessageType,
            final ProtectionProvider protectionProvider,
            final Function<PKIMessage, PKIMessage> cmpClient) throws Exception {
        final KeyPair keyPair = getKeyGenerator().generateKeyPair();
        final CertTemplateBuilder ctb = new CertTemplateBuilder()
                .setPublicKey(SubjectPublicKeyInfo
                        .getInstance(keyPair.getPublic().getEncoded()))
                .setSubject(new X500Name("CN=Subject"));

        final PKIBody crBody = PkiMessageGenerator.generateIrCrKurBody(
                requestMesssageType, ctb.build(), null, keyPair.getPrivate());

        final PKIMessage cr = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest(), protectionProvider, crBody);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(cr));
        }
        final PKIMessage crResponse = cmpClient.apply(cr);

        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(crResponse));
        }
        assertEquals("message type", expectedResponseMessageType,
                crResponse.getBody().getType());

        final CMPCertificate enrolledCertificate =
                ((CertRepMessage) crResponse.getBody().getContent())
                        .getResponse()[0].getCertifiedKeyPair()
                                .getCertOrEncCert().getCertificate();

        final PKIMessage certConf =
                PkiMessageGenerator.generateAndProtectMessage(
                        new HeaderProviderForTest(crResponse.getHeader()),
                        protectionProvider, PkiMessageGenerator
                                .generateCertConfBody(enrolledCertificate));

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(certConf));
        }
        final PKIMessage pkiConf = cmpClient.apply(certConf);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(pkiConf));
        }
        assertEquals("message type", PKIBody.TYPE_CONFIRM,
                pkiConf.getBody().getType());

        return new EnrollmentResult(enrolledCertificate, keyPair.getPrivate());
    }

    static public EnrollmentResult executeCrmfCertificateRequestWithoutKey(
            final int requestMesssageType,
            final int expectedResponseMessageType,
            final ProtectionProvider protectionProvider,
            final Function<PKIMessage, PKIMessage> cmpClient,
            final CmsDecryptor decryptor, final DataSignVerifier verifier)
            throws Exception {
        // grab the key parameters from a real public key
        final KeyPair keyPair = getKeyGenerator().generateKeyPair();
        final SubjectPublicKeyInfo subjectPublicKey = SubjectPublicKeyInfo
                .getInstance(keyPair.getPublic().getEncoded());
        final byte[] publicKey = new byte[0];
        final CertTemplateBuilder ctb = new CertTemplateBuilder()
                .setPublicKey(new SubjectPublicKeyInfo(
                        subjectPublicKey.getAlgorithm(), publicKey))
                .setSubject(new X500Name("CN=Subject"));

        final CertTemplate template = ctb.build();
        CertTemplate.getInstance(template.getEncoded());
        final PKIBody crBody = PkiMessageGenerator
                .generateIrCrKurBody(requestMesssageType, template, null, null);

        final PKIMessage cr = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest(), protectionProvider, crBody);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(cr));
        }
        final PKIMessage crResponse = cmpClient.apply(cr);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(crResponse));
        }
        assertEquals("message type", expectedResponseMessageType,
                crResponse.getBody().getType());

        final CertifiedKeyPair certifiedKeyPair =
                ((CertRepMessage) crResponse.getBody().getContent())
                        .getResponse()[0].getCertifiedKeyPair();
        final CMPCertificate enrolledCertificate =
                certifiedKeyPair.getCertOrEncCert().getCertificate();
        // recover private key
        final PrivateKey recoveredKey = verifier
                .verifySignedKey(decryptor.decrypt(EnvelopedData.getInstance(
                        certifiedKeyPair.getPrivateKey().getValue())));
        assertNotNull(recoveredKey);

        final PKIMessage certConf =
                PkiMessageGenerator.generateAndProtectMessage(
                        new HeaderProviderForTest(crResponse.getHeader()),
                        protectionProvider, PkiMessageGenerator
                                .generateCertConfBody(enrolledCertificate));

        // try to use received certificate and key
        final DataSigner testSigner = new DataSigner(recoveredKey,
                CertUtility.certificateFromCmpCertificate(enrolledCertificate));
        final byte[] msgToSign = "Hello Signer, I am the message".getBytes();
        assertArrayEquals(msgToSign, DataSignVerifier
                .verifySignature(testSigner.signData(msgToSign).getEncoded()));

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(certConf));
        }
        final PKIMessage pkiConf = cmpClient.apply(certConf);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(pkiConf));
        }
        assertEquals("message type", PKIBody.TYPE_CONFIRM,
                pkiConf.getBody().getType());

        return new EnrollmentResult(enrolledCertificate, keyPair.getPrivate());
    }

    static public EnrollmentResult executeP10CertificateRequest(
            final ProtectionProvider protectionProvider,
            final Function<PKIMessage, PKIMessage> cmpClient) throws Exception {
        final KeyPair keyPair = getKeyGenerator().generateKeyPair();
        final JcaPKCS10CertificationRequestBuilder p10Builder =
                new JcaPKCS10CertificationRequestBuilder(
                        new X500Name("CN=Subject"), keyPair.getPublic());
        final PrivateKey privateKey = keyPair.getPrivate();
        String algorithm = privateKey.getAlgorithm();
        if (algorithm.startsWith("EC")) {
            algorithm = "ECDSA";
        }
        final String signatureAlgorithm = "SHA256with" + algorithm;
        final ContentSigner signer =
                new JcaContentSignerBuilder(signatureAlgorithm)
                        .build(privateKey);
        final PKCS10CertificationRequest p10Request = p10Builder.build(signer);
        final PKIBody p10Body = new PKIBody(PKIBody.TYPE_P10_CERT_REQ,
                p10Request.toASN1Structure());
        final PKIMessage cr = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest(), protectionProvider, p10Body);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(cr));
        }
        final PKIMessage crResponse = cmpClient.apply(cr);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(crResponse));
        }
        final CMPCertificate enrolledCertificate =
                ((CertRepMessage) crResponse.getBody().getContent())
                        .getResponse()[0].getCertifiedKeyPair()
                                .getCertOrEncCert().getCertificate();

        final PKIMessage certConf =
                PkiMessageGenerator.generateAndProtectMessage(
                        new HeaderProviderForTest(crResponse.getHeader()),
                        protectionProvider, PkiMessageGenerator
                                .generateCertConfBody(enrolledCertificate));

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(certConf));
        }
        final PKIMessage pkiConf = cmpClient.apply(certConf);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(pkiConf));
        }
        assertEquals("message type", PKIBody.TYPE_CONFIRM,
                pkiConf.getBody().getType());

        return new EnrollmentResult(enrolledCertificate, privateKey);
    }
}
