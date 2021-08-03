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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.x509.KeyPurposeId;

/**
 * these constants should later go to {@link CMPObjectIdentifiers}
 *
 *
 */
public interface NewCMPObjectIdentifiers extends CMPObjectIdentifiers {

    ASN1ObjectIdentifier it_caCerts =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.17");

    ASN1ObjectIdentifier it_rootCaKeyUpdate =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.18");

    ASN1ObjectIdentifier it_certReqTemplate =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.19");

    ASN1ObjectIdentifier it_rootCaCert =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.20");

    ASN1ObjectIdentifier it_certProfile =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.21");

    ASN1ObjectIdentifier regCtrl_algId = id_regCtrl.branch("11");

    ASN1ObjectIdentifier regCtrl_rsaKeyLen = id_regCtrl.branch("12");

    ASN1ObjectIdentifier mod_cmp2021_88 =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.0.99");

    ASN1ObjectIdentifier mod_cmp2021_02 =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.0.100");

    ASN1ObjectIdentifier pbmac1 =
            new ASN1ObjectIdentifier("1.2.840.113549.1.5.14");

    KeyPurposeId id_kp_cmKGA = KeyPurposeId
            .getInstance(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.32"));

}
