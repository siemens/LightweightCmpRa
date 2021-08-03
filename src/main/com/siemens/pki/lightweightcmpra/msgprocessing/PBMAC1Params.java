/*
 *  Copyright (c) 2021 Siemens AG
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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/*
 * from https://datatracker.ietf.org/doc/html/rfc8018
 *
 * PBMAC1-params ::= SEQUENCE {
 * keyDerivationFunc AlgorithmIdentifier {{PBMAC1-KDFs}},
 * messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}} }
 */
public class PBMAC1Params extends ASN1Object {
    public static PBMAC1Params getInstance(final Object o) {
        if (o instanceof PBMAC1Params) {
            return (PBMAC1Params) o;
        } else if (o != null) {
            return new PBMAC1Params(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    private final AlgorithmIdentifier keyDerivationFunc;

    private final AlgorithmIdentifier messageAuthScheme;

    public PBMAC1Params(final AlgorithmIdentifier keyDerivationFunc,
            final AlgorithmIdentifier messageAuthScheme) {

        this.keyDerivationFunc = keyDerivationFunc;
        this.messageAuthScheme = messageAuthScheme;
    }

    private PBMAC1Params(final ASN1Sequence sequence) {
        if (sequence.size() != 2) {
            throw new IllegalArgumentException(
                    "ASN.1 SEQUENCE should be of length 2");
        }
        this.keyDerivationFunc =
                AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
        this.messageAuthScheme =
                AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
    }

    public AlgorithmIdentifier getKeyDerivationFunc() {
        return keyDerivationFunc;
    }

    public AlgorithmIdentifier getMessageAuthScheme() {
        return messageAuthScheme;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        final ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(keyDerivationFunc);
        v.add(messageAuthScheme);
        return new DERSequence(v);
    }

}