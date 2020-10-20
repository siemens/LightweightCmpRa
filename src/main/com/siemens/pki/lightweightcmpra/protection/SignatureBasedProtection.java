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

import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

import com.siemens.pki.lightweightcmpra.config.xmlparser.CMPCREDENTIALS.Out.SignatureBased;
import com.siemens.pki.lightweightcmpra.config.xmlparser.NESTEDENDPOINTCONFIGURATION.Out;
import com.siemens.pki.lightweightcmpra.cryptoservices.BaseCredentialService;
import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.cryptoservices.CmsEncryptorBase;
import com.siemens.pki.lightweightcmpra.cryptoservices.KeyAgreementEncryptor;
import com.siemens.pki.lightweightcmpra.cryptoservices.KeyTransportEncryptor;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;

/**
 * a {@link ProtectionProvider} enforcing a CMP message with signature based
 * protection
 */
public class SignatureBasedProtection extends BaseCredentialService
        implements ProtectionProvider {

    private final DEROctetString senderKid;
    private final GeneralName senderName;
    private final List<CMPCertificate> extraCerts;

    /**
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     *
     * @throws Exception
     *             in case of error
     */
    public SignatureBasedProtection(final Out config) throws Exception {
        this(config.getKeyStorePath(),
                config.getKeyStorePassword().toCharArray());
    }

    /**
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     *
     * @throws Exception
     *             in case of error
     */
    public SignatureBasedProtection(final SignatureBased config)
            throws Exception {
        this(config.getKeyStorePath(),
                config.getKeyStorePassword().toCharArray());
    }

    /**
     * @param keyStorePath
     *            path to load the protecting keystore
     * @param password
     *            password to open the protecting keystore
     */
    public SignatureBasedProtection(final String keyStorePath,
            final char[] password) throws Exception {
        super(keyStorePath, password);

        senderName = new GeneralName(X500Name.getInstance(
                getEndCertificate().getSubjectX500Principal().getEncoded()));
        senderKid = CertUtility
                .extractSubjectKeyIdentifierFromCert(getEndCertificate());
        extraCerts = Arrays.asList(
                CertUtility.cmpCertificatesFromCertificates(getCertChain()));
    }

    @Override
    public CmsEncryptorBase getKeyEncryptor(
            final CMPCertificate endEntityCertificate) throws Exception {
        if (endEntityCertificate == null) {
            throw new CmpProcessingException("downstream",
                    PKIFailureInfo.notAuthorized,
                    "private key encryption failed, no end etity certificate available");
        }
        final X509Certificate endEntityCertificateAsX509 =
                CertUtility.certificateFromCmpCertificate(endEntityCertificate);
        final boolean[] keyUsage = endEntityCertificateAsX509.getKeyUsage();
        if (keyUsage[4]) {
            // keyAgreement
            return new KeyAgreementEncryptor(this, endEntityCertificateAsX509);
        }
        if (keyUsage[2]) {
            // keyEncipherment
            return new KeyTransportEncryptor(endEntityCertificateAsX509);
        }
        throw new CmpProcessingException("downstream",
                PKIFailureInfo.notAuthorized,
                "private key encryption failed, no credentials with proper key usage available");

    }

    @Override
    public List<CMPCertificate> getProtectingExtraCerts() {
        return extraCerts;
    }

    @Override
    public AlgorithmIdentifier getProtectionAlg() {
        return getSignatureAlgorithm();
    }

    @Override
    public DERBitString getProtectionFor(final ProtectedPart protectedPart)
            throws Exception {
        final Signature sig =
                Signature.getInstance(getSignatureAlgorithmName());
        sig.initSign(getPrivateKey());
        sig.update(protectedPart.getEncoded(ASN1Encoding.DER));
        return new DERBitString(sig.sign());
    }

    @Override
    public GeneralName getSender() {
        return senderName;
    }

    @Override
    public DEROctetString getSenderKID() {
        return senderKid;
    }

}
