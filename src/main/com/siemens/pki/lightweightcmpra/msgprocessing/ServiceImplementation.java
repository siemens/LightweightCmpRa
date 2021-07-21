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

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;

import com.siemens.pki.lightweightcmpra.config.xmlparser.Configuration.ServiceConfiguration;
import com.siemens.pki.lightweightcmpra.config.xmlparser.Configuration.ServiceConfiguration.Response;
import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;
import com.siemens.pki.lightweightcmpra.msgvalidation.BaseCmpException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;

/**
 * implementation of a GENM service composed from
 * some {@link Function<ASN1ObjectIdentifier, PKIBody>} handlers and a
 * {@link BasicDownstream}
 *
 */
public class ServiceImplementation extends BasicDownstream {

    private final Map<ASN1ObjectIdentifier, Function<ASN1ObjectIdentifier, PKIBody>> responseMap =
            new HashMap<>();

    private final Function<ASN1ObjectIdentifier, PKIBody> COULD_NOT_HANDLE_OID_HANDLER =
            oid -> new PKIBody(PKIBody.TYPE_GEN_REP,
                    new GenRepContent(new InfoTypeAndValue(oid)));

    /**
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @throws Exception
     *             in case of error
     */
    public ServiceImplementation(final ServiceConfiguration config)
            throws Exception {
        super(config.getDownstream(), false, PKIBody.TYPE_GEN_MSG);
        for (final Response aktResponse : config.getResponse()) {
            if (aktResponse.getSequenceOfCMPCertificate() != null) {
                responseMap.put(
                        aktResponse.getServingOid() != null
                                ? new ASN1ObjectIdentifier(
                                        aktResponse.getServingOid())
                                : NewCMPObjectIdentifiers.it_caCerts,
                        new SequenceOfCMPCertificateResponse(
                                aktResponse.getSequenceOfCMPCertificate()));
            } else if (aktResponse.getCAKeyUpdAnnContent() != null) {
                responseMap.put(
                        aktResponse.getServingOid() != null
                                ? new ASN1ObjectIdentifier(
                                        aktResponse.getServingOid())
                                : NewCMPObjectIdentifiers.it_rootCaKeyUpdate,
                        new CAKeyUpdAnnContentResponse(
                                aktResponse.getCAKeyUpdAnnContent()));
            } else if (aktResponse.getAnyAsn1Content() != null) {
                responseMap.put(
                        aktResponse.getServingOid() != null
                                ? new ASN1ObjectIdentifier(
                                        aktResponse.getServingOid())
                                : NewCMPObjectIdentifiers.it_certReqTemplate,
                        new AnyAsn1ContentResponse(
                                aktResponse.getAnyAsn1Content()));
            }
        }
    }

    @Override
    protected PKIMessage handleValidatedInputMessage(final PKIMessage msg) {
        try {
            final InfoTypeAndValue itav =
                    ((GenMsgContent) msg.getBody().getContent())
                            .toInfoTypeAndValueArray()[0];
            final ASN1ObjectIdentifier infoType = itav.getInfoType();
            final Function<ASN1ObjectIdentifier, PKIBody> handler = responseMap
                    .getOrDefault(infoType, COULD_NOT_HANDLE_OID_HANDLER);
            return PkiMessageGenerator.generateAndProtectMessage(
                    PkiMessageGenerator.buildRespondingHeaderProvider(msg),
                    ProtectionProvider.NO_PROTECTION, handler.apply(infoType));
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Exception e) {
            throw new CmpProcessingException(INTERFACE_NAME, e);
        }
    }
}
