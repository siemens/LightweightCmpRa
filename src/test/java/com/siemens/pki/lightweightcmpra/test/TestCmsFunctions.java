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

import com.siemens.pki.cmpracomponent.util.MessageDumper;
import com.siemens.pki.lightweightcmpra.configuration.VerificationContextImpl;
import com.siemens.pki.lightweightcmpra.test.framework.BaseCredentialService;
import com.siemens.pki.lightweightcmpra.test.framework.CertUtility;
import com.siemens.pki.lightweightcmpra.test.framework.CmsDecryptor;
import com.siemens.pki.lightweightcmpra.test.framework.CmsEncryptorBase;
import com.siemens.pki.lightweightcmpra.test.framework.DataSignVerifier;
import com.siemens.pki.lightweightcmpra.test.framework.DataSigner;
import com.siemens.pki.lightweightcmpra.test.framework.KeyAgreementEncryptor;
import com.siemens.pki.lightweightcmpra.test.framework.KeyPairGeneratorFactory;
import com.siemens.pki.lightweightcmpra.test.framework.KeyTransportEncryptor;
import com.siemens.pki.lightweightcmpra.test.framework.PasswordEncryptor;
import com.siemens.pki.lightweightcmpra.test.framework.TestUtils;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestCmsFunctions {
    static BaseCredentialService lraCredentials;

    static BaseCredentialService eeCredentials;

    private static final Logger LOGGER = LoggerFactory.getLogger(TestCmsFunctions.class);
    public static final File CONFIG_DIRECTORY =
            new File("./src/test/java/com/siemens/pki/lightweightcmpra/test/config");

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        Security.addProvider(CertUtility.BOUNCY_CASTLE_PROVIDER);
        ConfigFileLoader.setConfigFileBase(CONFIG_DIRECTORY);
        lraCredentials =
                new BaseCredentialService("credentials/CMP_CA_Keystore.p12", TestUtils.getPasswordAsCharArray());
        eeCredentials =
                new BaseCredentialService("credentials/CMP_EE_Keystore.p12", TestUtils.getPasswordAsCharArray());
    }

    private X509Certificate createSelfsignedCertificate(final String subject, final KeyPair keypair)
            throws PEMException, NoSuchAlgorithmException, CertIOException, CertificateEncodingException,
                    CertificateException, OperatorCreationException {
        final long now = System.currentTimeMillis();
        final PublicKey pubKey = keypair.getPublic();
        final X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(
                new X500Principal(subject),
                BigInteger.valueOf(now),
                new Date(now - 60 * 60 * 1000L),
                new Date(now + 100 * 60 * 60 * 1000L),
                new X500Principal(subject),
                pubKey);

        final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        v3CertBldr.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pubKey));
        v3CertBldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pubKey));
        v3CertBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        final JcaContentSignerBuilder signerBuilder =
                new JcaContentSignerBuilder("SHA384withRSA").setProvider(CertUtility.BOUNCY_CASTLE_PROVIDER);

        return new JcaX509CertificateConverter()
                .setProvider(CertUtility.BOUNCY_CASTLE_PROVIDER)
                .getCertificate(v3CertBldr.build(signerBuilder.build(keypair.getPrivate())));
    }

    private void testDataEncryption(final CmsEncryptorBase encryptor, final CmsDecryptor decryptor)
            throws IOException, CMSException {
        final byte[] msgToEncrypt = "Hello Encryptor, I am the message".getBytes();
        final EnvelopedData encrypted = encryptor.encrypt(msgToEncrypt);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("EnvelopedData:\n" + MessageDumper.dumpAsn1Object(encrypted));
        }
        Assert.assertArrayEquals(msgToEncrypt, decryptor.decrypt(encrypted));
    }

    @Test
    public void testDataSigning() throws Exception {
        final DataSigner signer = new DataSigner("credentials/CMP_CA_Keystore.p12", TestUtils.getPasswordAsCharArray());
        final byte[] msgToSign = "Hello Signer, I am the message".getBytes();
        final SignedData signedData = signer.signData(msgToSign);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("CMSSignedData:\n" + MessageDumper.dumpAsn1Object(signedData));
        }
        final byte[] signedAndEncoded = signedData.getEncoded();
        final VerificationContextImpl verifierConfig =
                TestUtils.createVerificationContext("credentials/CMP_CA_Root.pem");
        final DataSignVerifier verifier = new DataSignVerifier(verifierConfig);
        Assert.assertArrayEquals(msgToSign, verifier.verifySignatureAndTrust(signedAndEncoded));
    }

    private void testKeyagreementBasedKeyEncryption(final KeyPair kp)
            throws GeneralSecurityException, Exception, CMSException, IOException, KeyStoreException,
                    CertificateException, NoSuchAlgorithmException {
        final CmsEncryptorBase encryptor = new KeyAgreementEncryptor(
                "credentials/CMP_CA_Keystore.p12", TestUtils.getPassword(), "credentials/CMP_EE_Chain.pem");
        final DataSigner signer = new DataSigner("credentials/CMP_CA_Keystore.p12", TestUtils.getPasswordAsCharArray());
        final EnvelopedData encryptedKey = encryptor.encrypt(signer.signPrivateKey(kp.getPrivate()));

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("EnvelopedData;\n" + MessageDumper.dumpAsn1Object(encryptedKey));
        }
        final VerificationContextImpl verifierConfig =
                TestUtils.createVerificationContext("credentials/CMP_CA_Root.pem");
        final DataSignVerifier verifier = new DataSignVerifier(verifierConfig);
        final CmsDecryptor decryptor =
                new CmsDecryptor(eeCredentials.getEndCertificate(), eeCredentials.getPrivateKey(), null);
        final PrivateKey recoveredKey = verifier.verifySignedKey(decryptor.decrypt(encryptedKey));
        Assert.assertEquals(recoveredKey, kp.getPrivate());
    }

    @Test
    public void testKeyagreementBasedKeyEncryptionEC() throws Exception {
        final KeyPair kp =
                KeyPairGeneratorFactory.getEcKeyPairGenerator("secp256r1").generateKeyPair();
        testKeyagreementBasedKeyEncryption(kp);
    }

    @Test
    public void testKeyagreementBasedKeyEncryptionRSA() throws Exception {
        final KeyPair kp = KeyPairGeneratorFactory.getRsaKeyPairGenerator(2048).generateKeyPair();
        testKeyagreementBasedKeyEncryption(kp);
    }

    @Test
    public void testKeytransportBasedDataEncryption() throws Exception {
        final KeyPair keyPair =
                KeyPairGeneratorFactory.getRsaKeyPairGenerator(2048).generateKeyPair();
        final X509Certificate certificate = createSelfsignedCertificate("CN=MySelf", keyPair);
        final CmsEncryptorBase encryptor = new KeyTransportEncryptor(certificate);
        final CmsDecryptor decryptor = new CmsDecryptor(certificate, keyPair.getPrivate(), null);
        testDataEncryption(encryptor, decryptor);
    }

    @Test
    public void testPasswordBasedDataEncryption() throws Exception {
        final char[] passphrase = "VerySecretPassword".toCharArray();
        final CmsEncryptorBase encryptor = new PasswordEncryptor("VerySecretPassword");
        final CmsDecryptor decryptor = new CmsDecryptor(null, null, passphrase);
        testDataEncryption(encryptor, decryptor);
    }
}
