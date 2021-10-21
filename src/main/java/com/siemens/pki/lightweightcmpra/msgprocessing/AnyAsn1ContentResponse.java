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

import java.util.function.Function;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;

import com.siemens.pki.lightweightcmpra.config.xmlparser.Configuration.ServiceConfiguration.Response.AnyAsn1Content;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;

/**
 * a handler able to return pre configured ASN1.1 content loaded from a file
 *
 * id-it-certReqTemplate OBJECT IDENTIFIER ::= {1 3 6 1 5 5 7 4 xxx}
 * CertReqTemplateValue ::= SEQUENCE {
 * certTemplate CertTemplate,
 * rsaKeyLen INTEGER OPTIONAL,
 * }
 *
 */
public class AnyAsn1ContentResponse
        implements Function<ASN1ObjectIdentifier, PKIBody> {

    private final ASN1Primitive content;

    /**
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @throws Exception
     *             in case of error
     */
    public AnyAsn1ContentResponse(final AnyAsn1Content config)
            throws Exception {
        try (final ASN1InputStream ain = new ASN1InputStream(ConfigFileLoader
                .getConfigFileAsStream(config.getSourceFile()));) {
            content = ain.readObject();
        }
    }

    @Override
    public PKIBody apply(final ASN1ObjectIdentifier oid) {
        return new PKIBody(PKIBody.TYPE_GEN_REP,
                new GenRepContent(new InfoTypeAndValue(oid, content)));
    }

}
