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

import java.io.FileOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
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
 * a helper class for writing a proper CertReqTemplateValue
 *
 */
public class CertReqTemplateValueWriter {

    static public void main(final String args[]) throws Exception {
        new CertReqTemplateValueWriter().writeCertReqTemplateValue(args[0]);
    }

    // KeyPurposeId.id_kp_serverAuth | KeyPurposeId.id_kp_clientAuth |
    // KeyUsage.cRLSign
    private Extension createExtendedKeyUsageExtension(
            final KeyPurposeId... extendedKeyUsages) throws IOException {
        return new Extension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(extendedKeyUsages).getEncoded());
    }

    // KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign
    private Extension createKeyUsageExtension(final int... keyUsages)
            throws IOException {
        int keyUsage = 0;
        for (final int aktUsage : keyUsages) {
            keyUsage |= aktUsage;
        }
        return new Extension(Extension.keyUsage, true,
                new KeyUsage(keyUsage).getEncoded());
    }

    // GeneralName.iPAddress, GeneralName.dNSName, GeneralName.rfc822Name
    private Extension createSubjectAlternativeNameExtension(
            final GeneralName... generalNames) throws IOException {
        final GeneralNamesBuilder gnb = new GeneralNamesBuilder();
        for (final GeneralName gn : generalNames) {
            gnb.addName(gn);
        }
        return new Extension(Extension.subjectAlternativeName, true,
                gnb.build().getEncoded());
    }

    private Extension createSubjectAlternativeNameExtension(
            final String... hostnames) throws IOException {
        final GeneralName[] generalNames = new GeneralName[hostnames.length];
        for (int i = 0; i < hostnames.length; i++) {
            generalNames[i] =
                    new GeneralName(GeneralName.dNSName, hostnames[i]);
        }
        return createSubjectAlternativeNameExtension(generalNames);
    }

    public void writeCertReqTemplateValue(final String outFile)
            throws Exception {
        final CertTemplateBuilder ctb = new CertTemplateBuilder();
        ctb.setSubject(new X500Name("CN=,OU=myDept,OU=myGroup"));
        final Extension[] extens = new Extension[] {
                createSubjectAlternativeNameExtension("www.myServer.com",
                        "1.2.3.4"),
                createKeyUsageExtension(KeyUsage.digitalSignature,
                        KeyUsage.keyAgreement),
                createExtendedKeyUsageExtension(KeyPurposeId.id_kp_clientAuth)};
        ctb.setExtensions(new Extensions(extens));
        final CertTemplate template = ctb.build();
        final ASN1Sequence certReqTemplateValue = new DERSequence(
                new ASN1Encodable[] {template, new ASN1Integer(2048)});
        final ASN1OutputStream out =
                ASN1OutputStream.create(new FileOutputStream(outFile));
        out.writeObject(certReqTemplateValue);
    }

}
