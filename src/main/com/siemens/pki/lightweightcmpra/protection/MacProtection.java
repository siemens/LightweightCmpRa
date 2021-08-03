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

package com.siemens.pki.lightweightcmpra.protection;

import java.security.SecureRandom;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

import com.siemens.pki.lightweightcmpra.cryptoservices.CmsEncryptorBase;
import com.siemens.pki.lightweightcmpra.cryptoservices.PasswordEncryptor;
import com.siemens.pki.lightweightcmpra.cryptoservices.WrappedMac;

/**
 * base class for MAC protection provider
 *
 *
 */
public abstract class MacProtection implements ProtectionProvider {

    /**
     * Random number generator
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    protected static final int DEFAULT_ITERATION_COUNT = 10_000;

    protected static byte[] getDefaultSalt() {
        final byte[] ret = new byte[16];
        RANDOM.nextBytes(ret);
        return ret;
    }

    private AlgorithmIdentifier protectionAlg;
    private final DEROctetString username;
    private WrappedMac protectingMac;
    protected final char[] passwordAsCharArrays;

    protected MacProtection(final String userName, final String password) {
        this.username =
                userName != null ? new DEROctetString(userName.getBytes())
                        : null;
        passwordAsCharArrays = password.toCharArray();
    }

    @Override
    public CmsEncryptorBase getKeyEncryptor(
            final CMPCertificate endEntityCertificate) throws Exception {
        return new PasswordEncryptor(passwordAsCharArrays);
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
    public synchronized DERBitString getProtectionFor(
            final ProtectedPart protectedPart) throws Exception {
        return new DERBitString(protectingMac
                .calculateMac(protectedPart.getEncoded(ASN1Encoding.DER)));
    }

    @Override
    public GeneralName getSender() {
        return null;
    }

    @Override
    public DEROctetString getSenderKID() {
        return username;
    }

    protected void setProtectingMac(final WrappedMac protectingMac) {
        this.protectingMac = protectingMac;
    }

    protected void setProtectionAlg(final AlgorithmIdentifier protectionAlg) {
        this.protectionAlg = protectionAlg;
    }

}
