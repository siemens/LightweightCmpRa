/*
 * Copyright (c) 2023 Siemens AG
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.siemens.pki.lightweightcmpra.plugin;

import com.siemens.pki.cmpracomponent.configuration.CheckAndModifyResult;
import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;

public class LocalInventoryInterfaceImpl implements InventoryInterface {
    /**
     * check and optionally modify a CRMF certificate request that was received in a
     * CMP ir, cr or kur message.
     *
     * @param transactionID      the transactionID of the CMP request message. The
     *                           transactionID can be used to correlate calls of
     *                           {@link #checkAndModifyCertRequest(byte[], String, byte[], String, byte[])}
     *                           and
     *                           {@link #learnEnrollmentResult(byte[], byte[], String, String, String)}.
     * @param requesterDn        Distinguished Name (DN) of the CMP requester. This
     *                           is the subject of the first certificate in the
     *                           extraCerts field of the CMP request or the sender
     *                           extracted from the PKI message header. If neither
     *                           signature-based protection was used nor the sender
     *                           field was set the requesterDn is <code>null</code>.
     *                           The DN is an X500 name formatted as string
     *                           according to the BouncyCastle library defaults.
     * @param certTemplate       the ASN.1 DER-encoded CertTemplate of the
     *                           certificate request as received from the requester.
     *                           Note that it may indicate central key generation,
     *                           optionally specifying key parameters.
     * @param requestedSubjectDn subject DN extracted from the CertTemplate of the
     *                           request or <code>null</code> if subject was not
     *                           present. The DN is an X500 name formatted as string
     *                           according to the BouncyCastle library defaults.
     *                           This parameter is provided for convenience.
     * @param pkiMessage         the ASN.1 DER-encoded CMP ir, cr or kur message
     * @return result of validation check
     */
    @Override
    public CheckAndModifyResult checkAndModifyCertRequest(byte[] transactionID, String requesterDn, byte[] certTemplate, String requestedSubjectDn, byte[] pkiMessage) {
        return new CheckAndModifyResult() {
            @Override
            public byte[] getUpdatedCertTemplate() {
                return null;
            }

            @Override
            public boolean isGranted() {
                return requestedSubjectDn.endsWith("domain.name");
            }
        };
    }

    /**
     * check PKCS#10 certificate request that was received in CMP p10cr message. Note
     * that such certificate request cannot be modified because it is self-signed by
     * the requester.
     *
     * @param transactionID      the transactionID of the CMP request message. The
     *                           transactionID can be used to correlate calls of
     *                           {@link #checkP10CertRequest(byte[], String, byte[], String, byte[])}
     *                           and
     *                           {@link #learnEnrollmentResult(byte[], byte[], String, String, String)}.
     * @param requesterDn        Distinguished Name (DN) of the CMP requester. This
     *                           is the subject of the first certificate in the
     *                           extraCerts field of the CMP request or the sender
     *                           extracted from the PKI message header. If neither
     *                           signature-based protection was used nor the sender
     *                           field was set the requesterDn is <code>null</code>.
     *                           The DN is an X500 name formatted as string
     *                           according to the BouncyCastle library defaults.
     * @param pkcs10CertRequest  the ASN.1 DER-encoded PKCS#10 certificate request
     *                           as received from a requester in a p10cr request.
     * @param requestedSubjectDn subject DN extracted from the
     *                           CertificationRequestInfo of the pkcs10CertRequest.
     *                           The DN is an X500 name formatted as string
     *                           according to the BouncyCastle library defaults.
     *                           This parameter is provided for convenience.
     * @param pkiMessage         the ASN.1 DER-encoded CMP p10cr message
     * @return <code>true</code> if the request is granted.
     */
    @Override
    public boolean checkP10CertRequest(byte[] transactionID, String requesterDn, byte[] pkcs10CertRequest, String requestedSubjectDn, byte[] pkiMessage) {
        return false;
    }

    /**
     * learn the enrollment status including any new certificate. May respond false
     * in case of internal processing error.
     *
     * @param transactionID the transactionID of the CMP request/response message.
     *                      The transactionID can be used to correlate calls of
     *                      {@link #checkAndModifyCertRequest(byte[], String, byte[], String, byte[])}
     *                      or
     *                      {@link #checkP10CertRequest(byte[], String, byte[], String, byte[])}
     *                      and
     *                      {@link #learnEnrollmentResult(byte[], byte[], String, String, String)}.
     * @param certificate   the new certificate, which is assumed to be ASN.1 DER
     *                      encoded, as returned by the CA. On enrollment failure,
     *                      <code>null</code> is given.
     * @param serialNumber  string representation of the certificate serial number.
     *                      In case of enrollment failure, <code>null</code> is
     *                      given. This parameter is provided for convenience.
     * @param subjectDN     the subject Distinguished Name extracted from the
     *                      certificate or from the certificate request in case of
     *                      enrollment failure. This parameter is provided for
     *                      convenience.
     * @param issuerDN      the issuer Distinguished Name extracted from the
     *                      certificate. In case of enrollment failure,
     *                      <code>null</code> is given. This parameter is provided
     *                      for convenience.
     * @return true on success
     */
    @Override
    public boolean learnEnrollmentResult(byte[] transactionID, byte[] certificate, String serialNumber, String subjectDN, String issuerDN) {
        return true;
    }
}
