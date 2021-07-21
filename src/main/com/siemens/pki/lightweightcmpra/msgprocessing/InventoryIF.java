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

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.cmp.PKIMessage;

import com.siemens.pki.lightweightcmpra.msgvalidation.CmpEnrollmentException;

/**
 *
 * interface of an inventory
 *
 */
public interface InventoryIF {

    InventoryIF DummyInventory = new InventoryIF() {

        @Override
        public PKIMessage checkAndModifyRequest(final PKIMessage request) {
            return request;
        }

        @Override
        public void storeCerificate(final X509Certificate enrolledCertificate,
                final PKIMessage responseFromUpstream) {
        }

    };

    /**
     * analyze and maybe modify the received request
     *
     * @param request
     *            request to analyze and maybe modify
     * @return modified request or unchanged request
     * @throws CmpEnrollmentException
     *             if request is not acceptable and should be answered with an
     *             CMP error
     */
    PKIMessage checkAndModifyRequest(PKIMessage request);

    /**
     * process and store enrolled certificate
     *
     * @param enrolledCertificate
     *            enrolled certificate
     * @param responseFromUpstream
     *            whole response
     */
    void storeCerificate(X509Certificate enrolledCertificate,
            PKIMessage responseFromUpstream);

}
