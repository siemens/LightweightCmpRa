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

import java.math.BigInteger;
import java.util.Date;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.config.xmlparser.Configuration.RestService;
import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.msggeneration.HeaderProvider;
import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;
import com.siemens.pki.lightweightcmpra.server.RestHttpServer;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

/**
 * implementation of a REST service composed from a {@link RaUpstream} and a
 * {@link RestHttpServer}
 *
 *
 */
public class RestServiceImplementation {
    private static final Logger LOGGER =
            LoggerFactory.getLogger(RestServiceImplementation.class);
    private final RaUpstream upstream;
    @SuppressWarnings("unused")
    private final RestHttpServer restHttpServer;

    private final GeneralName usedRecipient;

    /**
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @throws Exception
     *             in case of error
     */
    public RestServiceImplementation(final RestService config)
            throws Exception {
        upstream = new RaUpstream(config.getUpstream());
        restHttpServer = RestHttpServer.createRestHttpServerFromConfig(
                config.getRestHttpServer(), this);
        usedRecipient = new GeneralName(new X500Name(config.getRecipient()));
    }

    /**
     * send a revocation request to the upstream
     *
     * @param issuer
     *            issuer of the certificate to revoke
     * @param serialNumber
     *            serialNumber of the certificate to revoke
     * @return true if the certificate was revoked
     *
     * @throws Exception
     *             in case of error
     */
    public boolean doRevocation(final String issuerAsString,
            final String serialNumberAsString) throws Exception {

        final String upperSerialNumber = serialNumberAsString.toUpperCase();
        final String scrubbedSerialNumber =
                upperSerialNumber.replaceAll("[^0123456789ABCDEF]", "");
        final BigInteger serialNumber;
        if (upperSerialNumber.startsWith("0X")
                || upperSerialNumber.endsWith("H")
                || upperSerialNumber.matches(".*[ABCDEF].*")) {
            serialNumber = new BigInteger(scrubbedSerialNumber, 16);
        } else {
            serialNumber = new BigInteger(scrubbedSerialNumber);
        }
        final PKIBody rrBody = PkiMessageGenerator.generateRrBody(
                new X500Name(issuerAsString), new ASN1Integer(serialNumber));
        final BEROctetString transactionId =
                new BEROctetString(CertUtility.generateRandomBytes(20));
        final byte[] senderNonce = CertUtility.generateRandomBytes(20);
        final HeaderProvider headerProvider = new HeaderProvider() {

            @Override
            public InfoTypeAndValue[] getGeneralInfo() {
                return null;
            }

            @Override
            public ASN1GeneralizedTime getMessageTime() {
                return new DERGeneralizedTime(new Date());
            }

            @Override
            public int getPvno() {
                return PKIHeader.CMP_2000;
            }

            @Override
            public GeneralName getRecipient() {
                return usedRecipient;
            }

            @Override
            public byte[] getRecipNonce() {
                return null;
            }

            @Override
            public GeneralName getSender() {
                return null;
            }

            @Override
            public byte[] getSenderNonce() {
                return senderNonce;
            }

            @Override
            public ASN1OctetString getTransactionID() {
                return transactionId;
            }

        };
        // the upstream will do the protection if configured
        final PKIMessage request =
                PkiMessageGenerator.generateAndProtectMessage(headerProvider,
                        ProtectionProvider.NO_PROTECTION, rrBody);
        final PKIMessage response = upstream.apply(request);
        if (response == null) {
            LOGGER.error("no response to revocation request");
            return false;
        }
        if (response.getBody().getType() != PKIBody.TYPE_REVOCATION_REP) {
            LOGGER.error("unexpected response to revocation request");
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn("got:\n" + MessageDumper.dumpPkiMessage(response));
            }
            return false;
        }
        final RevRepContent content =
                (RevRepContent) response.getBody().getContent();
        final BigInteger status = content.getStatus()[0].getStatus();
        return BigInteger.ZERO.equals(status) // granted
                || BigInteger.ONE.equals(status); // grantedWithMods

    }
}
