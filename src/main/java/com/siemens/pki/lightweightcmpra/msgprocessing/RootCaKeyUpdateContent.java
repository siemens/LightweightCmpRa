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

// this type should be moved to package org.bouncycastle.asn1.cmp
package com.siemens.pki.lightweightcmpra.msgprocessing;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cmp.CMPCertificate;

/**
 * the RootCaKeyUpdateContent as defined in
 * https://datatracker.ietf.org/doc/draft-ietf-lamps-cmp-updates/
 *
 * RootCaKeyUpdateContent ::= SEQUENCE {
 * newWithNew CMPCertificate,
 * newWithOld [0] CMPCertificate OPTIONAL,
 * oldWithNew [1] CMPCertificate OPTIONAL
 * }
 *
 *
 */
public class RootCaKeyUpdateContent extends ASN1Object {

    public static RootCaKeyUpdateContent getInstance(final Object o) {
        if (o instanceof RootCaKeyUpdateContent) {
            return (RootCaKeyUpdateContent) o;
        }

        if (o != null) {
            return new RootCaKeyUpdateContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private CMPCertificate oldWithNew;

    private CMPCertificate newWithOld;

    private final CMPCertificate newWithNew;

    public RootCaKeyUpdateContent(final CMPCertificate newWithNew,
            final CMPCertificate newWithOld, final CMPCertificate oldWithNew) {
        this.newWithNew = newWithNew;
        this.newWithOld = newWithOld;
        this.oldWithNew = oldWithNew;
    }

    private RootCaKeyUpdateContent(final ASN1Sequence seq) {
        final Enumeration<?> en = seq.getObjects();

        newWithNew = CMPCertificate.getInstance(en.nextElement());

        while (en.hasMoreElements()) {
            final ASN1TaggedObject tObj =
                    ASN1TaggedObject.getInstance(en.nextElement());

            switch (tObj.getTagNo()) {
            case 0:
                newWithOld = CMPCertificate.getInstance(tObj.getBaseObject());
                break;
            case 1:
                oldWithNew = CMPCertificate.getInstance(tObj.getBaseObject());
                break;
            default:
                throw new IllegalArgumentException(
                        "unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public CMPCertificate getNewWithNew() {
        return newWithNew;
    }

    public CMPCertificate getNewWithOld() {
        return newWithOld;
    }

    public CMPCertificate getOldWithNew() {
        return oldWithNew;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        final ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(newWithNew);

        addOptional(v, 0, newWithOld);
        addOptional(v, 1, oldWithNew);

        return new DERSequence(v);
    }

    private void addOptional(final ASN1EncodableVector v, final int tagNo,
            final ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }
}
