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
package com.siemens.pki.lightweightcmpra.protection;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

import com.siemens.pki.lightweightcmpra.config.xmlparser.MACCREDENTIAL;
import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.cryptoservices.CmsEncryptorBase;
import com.siemens.pki.lightweightcmpra.cryptoservices.PasswordEncryptor;

/**
 * a {@link ProtectionProvider} enforcing a CMP message with password based MAC
 * protection
 */
public class PasswordBasedMacProtection implements ProtectionProvider {

    public static final ASN1ObjectIdentifier DEFAULT_OWF_OID =
            OIWObjectIdentifiers.idSHA1;

    //PKCSObjectIdentifiers.id_hmacWith* is also supported
    public static final ASN1ObjectIdentifier DEFAULT_MAC_OID =
            IANAObjectIdentifiers.hmacSHA1;

    private static final int DEFAULT_ITERATION_COUNT = 10_000;

    /**
     * Random number generator
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    private static byte[] getDefaultProtectionSalt() {
        final byte[] ret = new byte[16];
        RANDOM.nextBytes(ret);
        return ret;
    }

    private final AlgorithmIdentifier protectionAlg;

    private final DEROctetString username;
    private final char[] passwortAsCharArray;

    private final Mac protectingMac;

    /**
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     *
     * @throws Exception
     *             in the case of an internal error
     */
    public PasswordBasedMacProtection(final MACCREDENTIAL config)
            throws Exception {
        this(config.getPassword(), config.getUsername(),
                DEFAULT_ITERATION_COUNT, getDefaultProtectionSalt(),
                DEFAULT_OWF_OID, DEFAULT_MAC_OID);
    }

    /**
     *
     * @param password
     *            shared secret to protect with
     * @param userName
     *            senderKID to use, can be null
     * @param iterationCount
     * @param protectionSalt
     * @throws Exception
     *             in case of error
     */
    public PasswordBasedMacProtection(final String password,
            final String userName, final int iterationCount,
            final byte[] protectionSalt, final ASN1ObjectIdentifier owfOid,
            final ASN1ObjectIdentifier macOid) throws Exception {
        this.username =
                userName != null ? new DEROctetString(userName.getBytes())
                        : null;
        protectionAlg =
                new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac,
                        new PBMParameter(protectionSalt,
                                new AlgorithmIdentifier(owfOid), iterationCount,
                                new AlgorithmIdentifier(macOid)));
        passwortAsCharArray = password.toCharArray();
        final byte[] raSecret = password.getBytes(Charset.defaultCharset());
        byte[] calculatingBaseKey =
                new byte[raSecret.length + protectionSalt.length];
        System.arraycopy(raSecret, 0, calculatingBaseKey, 0, raSecret.length);
        System.arraycopy(protectionSalt, 0, calculatingBaseKey, raSecret.length,
                protectionSalt.length);
        // Construct the base key according to rfc4210, section 5.1.3.1
        final MessageDigest dig = MessageDigest.getInstance(owfOid.getId(),
                CertUtility.BOUNCY_CASTLE_PROVIDER);
        for (int i = 0; i < iterationCount; i++) {
            calculatingBaseKey = dig.digest(calculatingBaseKey);
            dig.reset();
        }
        protectingMac = Mac.getInstance(macOid.getId(),
                CertUtility.BOUNCY_CASTLE_PROVIDER);
        protectingMac
                .init(new SecretKeySpec(calculatingBaseKey, macOid.getId()));
    }

    @Override
    public CmsEncryptorBase getKeyEncryptor(
            final CMPCertificate endEntityCertificate) throws Exception {
        return new PasswordEncryptor(passwortAsCharArray);
    }

    @Override
    public List<CMPCertificate> getProtectingExtraCerts() {
        return null;
    }

    @Override
    public AlgorithmIdentifier getProtectionAlg() {
        return protectionAlg;
    }

    @Override
    public DERBitString getProtectionFor(final ProtectedPart protectedPart)
            throws Exception {
        protectingMac.reset();
        protectingMac.update(protectedPart.getEncoded(ASN1Encoding.DER));
        final byte[] bytes = protectingMac.doFinal();
        return new DERBitString(bytes);
    }

    @Override
    public GeneralName getSender() {
        return null;
    }

    @Override
    public DEROctetString getSenderKID() {
        return username;
    }

}
