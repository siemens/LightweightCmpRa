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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.Function;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;

import com.siemens.pki.lightweightcmpra.config.xmlparser.Configuration.ServiceConfiguration.Response.RootCaKeyUpdateContent;
import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;

/**
 * a handler able to return a pre configured
 * {@link com.siemens.pki.lightweightcmpra.msgprocessing.RootCaKeyUpdateContent}
 *
 */
public class RootCaKeyUpdateContentResponse
        implements Function<ASN1ObjectIdentifier, PKIBody> {

    private static CMPCertificate loadCertificate(final String filename)
            throws Exception {
        if (filename == null) {
            return null;
        }
        final List<X509Certificate> certs =
                CertUtility.loadCertificatesFromFile(filename);
        switch (certs.size()) {
        case 0:
            return null;
        case 1:
            return CertUtility.cmpCertificateFromCertificate(certs.get(0));
        default:
            throw new IOException(
                    "only one certificate allowed in " + filename);
        }
    }

    private final CMPCertificate oldWithNew;
    private final CMPCertificate newWithOld;
    private final CMPCertificate newWithNew;

    /**
     *
     * @param rootCaKeyUpdateContent
     *            {@link JAXB} configuration subtree from XML configuration file
     * @throws Exception
     *             in case of error
     */
    public RootCaKeyUpdateContentResponse(
            final RootCaKeyUpdateContent rootCaKeyUpdateContent)
            throws Exception {
        oldWithNew = loadCertificate(rootCaKeyUpdateContent.getOldWithNew());
        newWithOld = loadCertificate(rootCaKeyUpdateContent.getNewWithOld());
        newWithNew = loadCertificate(rootCaKeyUpdateContent.getNewWithNew());
    }

    /**
     * respond to incoming request for a specific OID
     */
    @Override
    public PKIBody apply(final ASN1ObjectIdentifier oid) {
        return new PKIBody(PKIBody.TYPE_GEN_REP,
                new GenRepContent(new InfoTypeAndValue(oid,
                        new com.siemens.pki.lightweightcmpra.msgprocessing.RootCaKeyUpdateContent(
                                newWithNew, newWithOld, oldWithNew))));
    }

}
