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
package com.siemens.pki.lightweightcmpra.test.framework;

import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import com.siemens.pki.lightweightcmpra.downstream.DownstreamInterface.ExFunction;
import com.siemens.pki.lightweightcmpra.downstream.online.CmpHttpServer;
import com.siemens.pki.lightweightcmpra.test.EnrollmentTestcaseBase;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIMessages;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevRepContentBuilder;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * a mocked Certificate Authority
 */
public class CmpCaMock implements ExFunction {

    private static final int MAX_LAST_RECEIVED = 10;

    private static final Logger LOGGER = LoggerFactory.getLogger(CmpCaMock.class);

    private static JcaPEMKeyConverter JCA_KEY_CONVERTER = new JcaPEMKeyConverter();

    private static CmpCaMock singleCaMock;

    private static final LinkedList<PKIMessage> lastReceivedMessages = new LinkedList<>();

    public static PKIMessage getLastReceivedRequest() {
        return lastReceivedMessages.getFirst();
    }

    public static PKIMessage getReceivedRequestAt(int index) {
        return lastReceivedMessages.get(index);
    }

    public static CmpCaMock launchSingleCaMock() throws InterruptedException {
        if (singleCaMock == null) {
            new Thread(
                            (Runnable) () -> {
                                try {
                                    singleCaMock = new CmpCaMock(
                                            "http://localhost:7000/ca",
                                            "credentials/ENROLL_Keystore.p12",
                                            "credentials/CMP_CA_Keystore.p12");
                                } catch (final Exception e) {
                                    EnrollmentTestcaseBase.LOGGER.error("CA start", e);
                                }
                            },
                            "CA thread")
                    .start();
            Thread.sleep(2000L);
        }
        lastReceivedMessages.clear();
        return singleCaMock;
    }

    public static void main(final String args[]) throws Exception {
        Security.addProvider(CertUtility.BOUNCY_CASTLE_PROVIDER);
        final String configFileDirectory = args[0];
        ConfigFileLoader.setConfigFileBase(new File(configFileDirectory));
        final String servingUrl = args[1];
        final String enrollmentCredentials = args[2];
        final String protectionCredentials = args[3];
        new CmpCaMock(servingUrl, enrollmentCredentials, protectionCredentials);
    }

    public static void stopSingleCaMock() {
        if (singleCaMock != null) {
            singleCaMock.stop();
            singleCaMock = null;
        }
    }

    private CmpHttpServer httpServer;

    private final ProtectionProvider caProtectionProvider;

    private final TrustChainAndPrivateKey enrollmentCredentials;

    public CmpCaMock(final String servingUrl, final String enrollmentCredentials, final String protectionCredentials)
            throws Exception {
        this.enrollmentCredentials =
                new TrustChainAndPrivateKey(enrollmentCredentials, TestUtils.getPasswordAsCharArray());
        caProtectionProvider =
                TestUtils.createSignatureBasedProtection(protectionCredentials, TestUtils.getPasswordAsCharArray());
        httpServer = new CmpHttpServer(new URL(servingUrl), this);
    }

    @Override
    public byte[] apply(final byte[] receivedMessageAsByte) throws Exception {
        final PKIMessage receivedMessage = PKIMessage.getInstance(receivedMessageAsByte);
        return handlePkiMessage(receivedMessage).getEncoded();
    }

    private CMPCertificate createCertificate(
            final X500Name subject, final SubjectPublicKeyInfo publicKey, final X509Certificate issuingCert)
            throws PEMException, NoSuchAlgorithmException, CertIOException, CertificateEncodingException,
                    CertificateException, OperatorCreationException {
        final long now = System.currentTimeMillis();
        final PublicKey pubKey = JCA_KEY_CONVERTER.getPublicKey(publicKey);
        final X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(
                issuingCert.getSubjectX500Principal(),
                BigInteger.valueOf(now),
                new Date(now - 60 * 60 * 1000L),
                new Date(now + 100 * 60 * 60 * 1000L),
                new X500Principal(subject.toString()),
                pubKey);

        final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        v3CertBldr.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pubKey));
        v3CertBldr.addExtension(
                Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuingCert));
        v3CertBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        final JcaContentSignerBuilder signerBuilder =
                new JcaContentSignerBuilder("SHA384withECDSA").setProvider(CertUtility.BOUNCY_CASTLE_PROVIDER);

        return CertUtility.cmpCertificateFromCertificate(new JcaX509CertificateConverter()
                .setProvider(CertUtility.BOUNCY_CASTLE_PROVIDER)
                .getCertificate(
                        v3CertBldr.build(signerBuilder.build(enrollmentCredentials.getPrivateKeyOfEndCertififcate()))));
    }

    private PKIMessage generateError(final PKIMessage receivedMessage, final String errorDetails) throws Exception {
        return PkiMessageGenerator.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(receivedMessage),
                caProtectionProvider,
                PkiMessageGenerator.generateErrorBody(PKIFailureInfo.badRequest, errorDetails));
    }

    private PKIMessage handleCertConfirm(final PKIMessage receivedMessage) throws Exception {
        return PkiMessageGenerator.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(receivedMessage),
                caProtectionProvider,
                PkiMessageGenerator.generatePkiConfirmBody());
    }

    private PKIMessage handleCrmfCerticateRequest(final PKIMessage receivedMessage) throws Exception {
        // get copy of enrollment chain
        final List<X509Certificate> issuingChain = enrollmentCredentials.getTrustChain();

        final X509Certificate issuingCert = issuingChain.get(0);
        final CertTemplate requestTemplate = ((CertReqMessages)
                        receivedMessage.getBody().getContent())
                .toCertReqMsgArray()[0]
                .getCertReq()
                .getCertTemplate();
        final SubjectPublicKeyInfo publicKey = requestTemplate.getPublicKey();
        final X500Name subject = requestTemplate.getSubject();
        final CMPCertificate cmpCertificateFromCertificate = createCertificate(subject, publicKey, issuingCert);

        // drop root certificate from copy
        issuingChain.remove(issuingChain.size() - 1);
        final List<CMPCertificate> issuingChainForExtraCerts = new ArrayList<>(issuingChain.size());
        for (final X509Certificate aktCert : issuingChain) {
            issuingChainForExtraCerts.add(CertUtility.cmpCertificateFromCertificate(aktCert));
        }
        return PkiMessageGenerator.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(receivedMessage),
                caProtectionProvider,
                null,
                PkiMessageGenerator.generateIpCpKupBody(
                        receivedMessage.getBody().getType() + 1, cmpCertificateFromCertificate),
                issuingChainForExtraCerts);
    }

    private PKIMessage handleNested(PKIMessage receivedMessage) throws Exception {
        final PKIMessages nestedMessages =
                (PKIMessages) receivedMessage.getBody().getContent();
        return handlePkiMessage(nestedMessages.toPKIMessageArray()[0]);
    }

    private PKIMessage handleP10CerticateRequest(final PKIMessage receivedMessage) throws Exception {
        // get copy of enrollment chain
        final List<X509Certificate> issuingChain = enrollmentCredentials.getTrustChain();

        final X509Certificate issuingCert = issuingChain.get(0);
        final CertificationRequestInfo certificationRequestInfo =
                ((CertificationRequest) receivedMessage.getBody().getContent()).getCertificationRequestInfo();
        final CMPCertificate cmpCertificateFromCertificate = createCertificate(
                certificationRequestInfo.getSubject(), certificationRequestInfo.getSubjectPublicKeyInfo(), issuingCert);

        // drop root certificate from copy
        issuingChain.remove(issuingChain.size() - 1);
        final List<CMPCertificate> issuingChainForExtraCerts = new ArrayList<>(issuingChain.size());
        for (final X509Certificate aktCert : issuingChain) {
            issuingChainForExtraCerts.add(CertUtility.cmpCertificateFromCertificate(aktCert));
        }
        return PkiMessageGenerator.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(receivedMessage),
                caProtectionProvider,
                null,
                PkiMessageGenerator.generateIpCpKupBody(PKIBody.TYPE_CERT_REP, cmpCertificateFromCertificate),
                issuingChainForExtraCerts);
    }

    private PKIMessage handlePkiMessage(final PKIMessage receivedMessage) throws Exception, IOException {
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't
            // enabled
            LOGGER.debug("CA: got:\n" + MessageDumper.dumpPkiMessage(receivedMessage));
        }
        lastReceivedMessages.addFirst(receivedMessage);
        while (lastReceivedMessages.size() > MAX_LAST_RECEIVED) {
            lastReceivedMessages.removeLast();
        }
        final PKIMessage ret;
        switch (receivedMessage.getBody().getType()) {
            case PKIBody.TYPE_INIT_REQ:
            case PKIBody.TYPE_CERT_REQ:
            case PKIBody.TYPE_KEY_UPDATE_REQ:
                ret = handleCrmfCerticateRequest(receivedMessage);
                break;
            case PKIBody.TYPE_P10_CERT_REQ:
                ret = handleP10CerticateRequest(receivedMessage);
                break;
            case PKIBody.TYPE_CERT_CONFIRM:
                ret = handleCertConfirm(receivedMessage);
                break;
            case PKIBody.TYPE_REVOCATION_REQ:
                ret = handleRevocationRequest(receivedMessage);
                break;
            case PKIBody.TYPE_NESTED:
                ret = handleNested(receivedMessage);
                break;
            default:
                ret = generateError(
                        receivedMessage,
                        "unsuported message type " + receivedMessage.getBody().getType());
        }
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't
            // enabled
            LOGGER.debug("CA: respond:\n" + MessageDumper.dumpPkiMessage(ret));
        }
        return ret;
    }

    private PKIMessage handleRevocationRequest(final PKIMessage receivedMessage) throws Exception {
        final RevRepContentBuilder rrcb = new RevRepContentBuilder();
        rrcb.add(new PKIStatusInfo(PKIStatus.granted));
        return PkiMessageGenerator.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(receivedMessage),
                caProtectionProvider,
                new PKIBody(PKIBody.TYPE_REVOCATION_REP, rrcb.build()));
    }

    public void stop() {
        if (httpServer != null) {
            httpServer.stop();
            httpServer = null;
        }
    }
}
