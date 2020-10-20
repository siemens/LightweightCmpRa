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
package com.siemens.pki.lightweightcmpra.msgprocessing;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.config.xmlparser.CMPCREDENTIALS;
import com.siemens.pki.lightweightcmpra.config.xmlparser.CMPCREDENTIALS.Out.SignatureBased;
import com.siemens.pki.lightweightcmpra.config.xmlparser.MACCREDENTIAL;
import com.siemens.pki.lightweightcmpra.cryptoservices.CmsEncryptorBase;
import com.siemens.pki.lightweightcmpra.cryptoservices.DataSigner;
import com.siemens.pki.lightweightcmpra.msggeneration.HeaderProvider;
import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;
import com.siemens.pki.lightweightcmpra.protection.PasswordBasedMacProtection;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;
import com.siemens.pki.lightweightcmpra.protection.SignatureBasedProtection;

/**
 * the {@link MsgOutputProtector} sets the right protection for outgoing
 * messages
 *
 */
public class MsgOutputProtector {

    enum ReprotectMode {
        reprotect, forward, strip
    }

    private static final Logger LOGGER =
            LoggerFactory.getLogger(MsgOutputProtector.class);

    private final ReprotectMode reprotectMode;

    private final ProtectionProvider protector;

    private final Map<ASN1OctetString, Set<CMPCertificate>> alreadSentExtraCerts;

    private DataSigner keySigner = null;

    /**
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @throws Exception
     */
    MsgOutputProtector(final CMPCREDENTIALS.Out config) throws Exception {
        if (config.isSuppressRedundantExtraCerts()) {
            LOGGER.debug("stripping enabled");
            alreadSentExtraCerts = new HashMap<>();
        } else {
            alreadSentExtraCerts = null;
        }
        final MACCREDENTIAL passwordBased = config.getPasswordBased();
        if (passwordBased != null) {
            protector = new PasswordBasedMacProtection(passwordBased);
        } else {
            final SignatureBased signatureBased = config.getSignatureBased();
            if (signatureBased != null) {
                protector = new SignatureBasedProtection(signatureBased);
                keySigner =
                        new DataSigner((SignatureBasedProtection) protector);
            } else {
                protector = ProtectionProvider.NO_PROTECTION;
            }
        }
        switch (config.getReprotectMode().toLowerCase()) {
        case "reprotect":
            reprotectMode = ReprotectMode.reprotect;
            break;
        case "forward":
            reprotectMode = ReprotectMode.forward;
            break;
        case "strip":
            reprotectMode = ReprotectMode.strip;
            break;
        default:
            throw new IllegalArgumentException(
                    "illegal reprotectMode: " + config.getReprotectMode());
        }
    }

    /**
     * generate and protect a new message
     *
     * @param headerProvider
     *            header of new message
     * @param body
     *            body of new message
     * @return new message
     * @throws Exception
     *             in case of error
     */
    public PKIMessage generateAndProtectMessage(
            final HeaderProvider headerProvider, final PKIBody body)
            throws Exception {
        return stripRedundantExtraCerts(PkiMessageGenerator
                .generateAndProtectMessage(headerProvider, protector, body));
    }

    /**
     * generate and protect a new message
     *
     * @param headerProvider
     *            header of new message
     * @param body
     *            body of new message
     * @param issuingChain
     *            enrollment chain
     * @return new message
     * @throws Exception
     *             in case of error
     */
    public PKIMessage generateAndProtectMessage(
            final HeaderProvider headerProvider, final PKIBody body,
            final List<CMPCertificate> issuingChain) throws Exception {
        return stripRedundantExtraCerts(
                PkiMessageGenerator.generateAndProtectMessage(headerProvider,
                        protector, body, issuingChain));
    }

    public CmsEncryptorBase getKeyEncryptor(
            final CMPCertificate endEntityCertificate) throws Exception {
        return protector.getKeyEncryptor(endEntityCertificate);
    }

    public DataSigner getKeySigner() {
        return keySigner;
    }

    /**
     * protect and forward a PKI message
     *
     * @param in
     *            message to forward
     * @param issuingChain
     *            chain belonging to an issued certificate in a IP, KUP or
     *            CP
     * @return protected message
     * @throws Exception
     *             in case of processing error
     */
    public PKIMessage protectAndForwardMessage(final PKIMessage in,
            final List<CMPCertificate> issuingChain) throws Exception {
        switch (reprotectMode) {
        case reprotect:
            return stripRedundantExtraCerts(
                    PkiMessageGenerator.generateAndProtectMessage(
                            PkiMessageGenerator
                                    .buildForwardingHeaderProvider(in),
                            protector, in.getBody(), issuingChain));
        case strip:
            return PkiMessageGenerator.generateAndProtectMessage(
                    PkiMessageGenerator.buildForwardingHeaderProvider(in),
                    ProtectionProvider.NO_PROTECTION, in.getBody(),
                    issuingChain);
        case forward:
            return stripRedundantExtraCerts(in);
        default:
            throw new IllegalArgumentException(
                    "internal error: invalid reprotectMode mode");
        }
    }

    private synchronized PKIMessage stripRedundantExtraCerts(PKIMessage msg) {
        if (alreadSentExtraCerts == null) {
            LOGGER.debug("stripping disabled");
            return msg;
        }
        final CMPCertificate[] extraCerts = msg.getExtraCerts();
        if (extraCerts == null || extraCerts.length <= 0) {
            LOGGER.debug("no extra certs, no stripping");
            return msg;
        }
        final ASN1OctetString transactionID =
                msg.getHeader().getTransactionID();
        final Set<CMPCertificate> alreadSentExtraCertsForTransactionID =
                alreadSentExtraCerts.get(transactionID);
        final List<CMPCertificate> extraCertsAsList =
                new LinkedList<>(Arrays.asList(extraCerts));
        if (alreadSentExtraCertsForTransactionID != null) {
            if (LOGGER.isDebugEnabled()) {
                // avoid unnecessary string processing, if debug isn't enabled
                LOGGER.debug("found cached for " + transactionID);
            }
            if (extraCertsAsList
                    .removeAll(alreadSentExtraCertsForTransactionID)) {
                // were able to drop some extra certs
                if (LOGGER.isDebugEnabled()) {
                    // avoid unnecessary string processing, if debug isn't enabled
                    LOGGER.debug("drop from " + msg.getExtraCerts().length
                            + " to " + extraCertsAsList.size());
                }
                msg = new PKIMessage(msg.getHeader(), msg.getBody(),
                        msg.getProtection(),
                        extraCertsAsList.isEmpty() ? null
                                : extraCertsAsList.toArray(
                                        new CMPCertificate[extraCertsAsList
                                                .size()]));
            }
            alreadSentExtraCertsForTransactionID.addAll(extraCertsAsList);
        } else {
            alreadSentExtraCerts.put(transactionID,
                    new HashSet<>(extraCertsAsList));
        }
        return msg;
    }
}
