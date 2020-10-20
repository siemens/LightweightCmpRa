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
package com.siemens.pki.lightweightcmpra.msgvalidation;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.config.xmlparser.CMPCREDENTIALS.In.SignatureBased;
import com.siemens.pki.lightweightcmpra.config.xmlparser.TRUSTCREDENTIALS;
import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.cryptoservices.TrustCredentialAdapter;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

/**
 * This class validates the signature based
 * protection of all incoming messages and generates proper error responses on
 * failed validation.
 */
public class SignatureProtectionValidator implements ValidatorIF {
    private static final Logger LOGGER =
            LoggerFactory.getLogger(SignatureProtectionValidator.class);

    private final TrustCredentialAdapter trustCredentialAdapter;

    private final Map<ASN1OctetString, X509Certificate> extraCertsCache;

    private final String interfaceName;

    public SignatureProtectionValidator(final String interfaceName,
            final SignatureBased config) throws Exception {
        this.interfaceName = interfaceName;
        trustCredentialAdapter = new TrustCredentialAdapter(config);
        if (config.isCacheExtraCerts()) {
            extraCertsCache = new HashMap<>();
        } else {
            extraCertsCache = null;
        }
    }

    public SignatureProtectionValidator(final String interfaceName,
            final TRUSTCREDENTIALS config) throws Exception {
        extraCertsCache = null;
        this.interfaceName = interfaceName;
        trustCredentialAdapter = new TrustCredentialAdapter(config);
    }

    private void checkProtectingSignature(final PKIMessage message,
            final ASN1ObjectIdentifier algorithm,
            final X509Certificate protectingCert)
            throws IOException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, SignatureException {
        final PKIHeader header = message.getHeader();
        final byte[] protectedBytes =
                new ProtectedPart(header, message.getBody())
                        .getEncoded(ASN1Encoding.DER);
        final byte[] protectionBytes = message.getProtection().getBytes();
        final Signature sig = Signature.getInstance(algorithm.getId(),
                CertUtility.BOUNCY_CASTLE_PROVIDER);
        sig.initVerify(protectingCert.getPublicKey());
        sig.update(protectedBytes);
        if (!sig.verify(protectionBytes, 0, protectionBytes.length)) {
            final String errorDetails =
                    "signature-based protection check failed, signature broken";
            LOGGER.warn(errorDetails);
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.wrongIntegrity, errorDetails);
        }
        final ASN1OctetString senderKID = header.getSenderKID();
        if (senderKID != null) {
            final DEROctetString kidFromCert = CertUtility
                    .extractSubjectKeyIdentifierFromCert(protectingCert);
            if (kidFromCert != null) {
                if (!senderKID.equals(kidFromCert)) {
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.badMessageCheck,
                            "mismatching senderKID in "
                                    + MessageDumper.msgTypeAsString(message));
                }
            } else {
                LOGGER.warn("missing senderKID in "
                        + MessageDumper.msgTypeAsString(message) + ", ignored");
            }
        }
    }

    @Override
    public void validate(final PKIMessage message)
            throws CmpProcessingException {
        try {
            final CMPCertificate[] extraCerts = message.getExtraCerts();
            if (extraCerts != null && extraCerts.length > 0) {
                // extraCerts available, use it for protection check
                final List<X509Certificate> extraCertsAsX509 =
                        CertUtility.certificatesFromCmpCertificates(extraCerts);
                // "extraCerts: If present, the first certificate in this field MUST be the protection certificate"
                final X509Certificate protectingCert = extraCertsAsX509.get(0);
                checkProtectingSignature(message,
                        message.getHeader().getProtectionAlg().getAlgorithm(),
                        protectingCert);
                if (trustCredentialAdapter.validateCertAgainstTrust(
                        protectingCert, extraCertsAsX509) == null) {
                    final String errorDetails =
                            "signature check failed, protecting cert not trusted";
                    LOGGER.warn(errorDetails);
                    throw new CmpValidationException(interfaceName,
                            PKIFailureInfo.wrongIntegrity, errorDetails);
                }
                final boolean[] keyUsage = protectingCert.getKeyUsage();
                if (keyUsage != null && !keyUsage[0]/* digitalSignature */) {
                    // be a littel bit more lazy about key usage for protectingCert,
                    // in case of RR or KUR it might be absent.
                    LOGGER.warn("the protecting certificate '"
                            + protectingCert.getSubjectDN()
                            + "' is not valid for digitalSignature, weakness ignored");
                }
                if (extraCertsCache != null) {
                    // extra cert caching enabled, keep protecting cert for later protection
                    // validation
                    extraCertsCache.put(message.getHeader().getTransactionID(),
                            protectingCert);
                }
                return;
            }
            // no extra certs in message
            if (extraCertsCache != null) {
                // try to get the protectingCert from the cache
                final X509Certificate protectingCert = extraCertsCache
                        .get(message.getHeader().getTransactionID());
                if (protectingCert != null) {
                    checkProtectingSignature(message, message.getHeader()
                            .getProtectionAlg().getAlgorithm(), protectingCert);
                    // protecting cert was already validated
                    return;
                }
            }
        } catch (final KeyException ex) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.wrongIntegrity,
                    "protecting cert has key not suitable for signing");
        } catch (final Exception ex) {
            throw new CmpProcessingException(interfaceName,
                    PKIFailureInfo.badMessageCheck,
                    ex.getClass() + ":" + ex.getLocalizedMessage());
        }
        throw new CmpValidationException(interfaceName,
                PKIFailureInfo.addInfoNotAvailable,
                "signature-based protection check failed, no extraCert provided and no cached protecting cert available");
    }

}
