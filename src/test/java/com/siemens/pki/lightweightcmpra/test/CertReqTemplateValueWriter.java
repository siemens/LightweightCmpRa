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
package com.siemens.pki.lightweightcmpra.test;

import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

/**
 *
 * a HELPER class for writing a proper CertReqTemplateValue
 *
 */
public class CertReqTemplateValueWriter {

    public static void writeCertReqTemplateValue(final File outFile) throws Exception {
        try (FileOutputStream outStream = new FileOutputStream(outFile)) {
            final CertTemplateBuilder ctb = new CertTemplateBuilder();
            ctb.setIssuer(new X500Name(new RDN[0]));
            ctb.setSubject(new X500Name("CN=,OU=myDept,OU=myGroup"));
            final GeneralNamesBuilder gnb = new GeneralNamesBuilder();
            gnb.addName(new GeneralName(GeneralName.dNSName, "www.myServer.com"));
            gnb.addName(new GeneralName(GeneralName.iPAddress, "0.0.0.0"));
            final Extension san = new Extension(
                    Extension.subjectAlternativeName, false, gnb.build().getEncoded(ASN1Encoding.DER));
            ctb.setExtensions(new Extensions(new Extension[] {
                san,
                createKeyUsageExtension(KeyUsage.digitalSignature, KeyUsage.keyAgreement),
                createExtendedKeyUsageExtension()
            }));
            final Controls controls = new Controls(new AttributeTypeAndValue[] {
                new AttributeTypeAndValue(CMPObjectIdentifiers.id_regCtrl_algId, new DERSequence(new ASN1Encodable[] {
                    new ASN1ObjectIdentifier("1.2.840.10045.2.1").toASN1Primitive(),
                    new ASN1ObjectIdentifier("1.2.840.10045.3.1.7").toASN1Primitive()
                })),
                new AttributeTypeAndValue(CMPObjectIdentifiers.id_regCtrl_rsaKeyLen, new ASN1Integer(2048))
            });
            final CertTemplate template = ctb.build();
            final ASN1Sequence certReqTemplateValue = new DERSequence(new ASN1Encodable[] {template, controls});
            final ASN1OutputStream out = ASN1OutputStream.create(outStream);
            System.out.println(MessageDumper.dumpAsn1Object(certReqTemplateValue));
            out.writeObject(certReqTemplateValue);
            System.out.println(ASN1Dump.dumpAsString(certReqTemplateValue, true));
        }
    }

    // KeyPurposeId.id_kp_serverAuth | KeyPurposeId.id_kp_clientAuth |
    // KeyUsage.cRLSign
    private static Extension createExtendedKeyUsageExtension(final KeyPurposeId... extendedKeyUsages)
            throws IOException {
        return new Extension(
                Extension.extendedKeyUsage,
                false,
                new ExtendedKeyUsage(extendedKeyUsages).getEncoded(ASN1Encoding.DER));
    }

    // KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign
    private static Extension createKeyUsageExtension(final int... keyUsages) throws IOException {
        int keyUsage = 0;
        for (final int aktUsage : keyUsages) {
            keyUsage |= aktUsage;
        }
        return new Extension(Extension.keyUsage, true, new KeyUsage(keyUsage).getEncoded(ASN1Encoding.DER));
    }

    // utility class
    private CertReqTemplateValueWriter() {}
}
