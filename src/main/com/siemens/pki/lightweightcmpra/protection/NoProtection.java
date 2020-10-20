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

import java.util.List;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

import com.siemens.pki.lightweightcmpra.cryptoservices.CmsEncryptorBase;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;

/**
 * a {@link ProtectionProvider} enforcing a CMP message without any protection
 *
 */
public class NoProtection implements ProtectionProvider {

    @Override
    public CmsEncryptorBase getKeyEncryptor(
            final CMPCertificate endEntityCertificate) {
        throw new CmpProcessingException("downstream",
                PKIFailureInfo.notAuthorized,
                "private key encryption failed, no credentials available");
    }

    @Override
    public List<CMPCertificate> getProtectingExtraCerts() {
        return null;
    }

    @Override
    public AlgorithmIdentifier getProtectionAlg() {
        return null;
    }

    @Override
    public DERBitString getProtectionFor(final ProtectedPart protectedPart)
            throws Exception {
        return null;
    }

    @Override
    public GeneralName getSender() {
        return null;
    }

    @Override
    public DEROctetString getSenderKID() {
        return null;
    }

}
