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
package com.siemens.pki.lightweightcmpra.msggeneration;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * data provider for all parameters required to build a CMP header.
 *
 */
public interface HeaderProvider {

    /**
     *
     * @return GeneralInfo (ImplicitConfirm, ConfirmWaitTime) used in CMP
     *         header.
     */
    InfoTypeAndValue[] getGeneralInfo();

    /**
     * @return MessageTime used in CMP header.
     */
    ASN1GeneralizedTime getMessageTime();

    /**
     * @return Recipient used in CMP header.
     */
    GeneralName getRecipient();

    /**
     * @return RecipNonce used in CMP header.
     */
    byte[] getRecipNonce();

    /**
     * @return Sender used in CMP header.
     */
    GeneralName getSender();

    /**
     * @return SenderNonce used in CMP header.
     */
    byte[] getSenderNonce();

    /**
     * @return TransactionID used in CMP header.
     */
    ASN1OctetString getTransactionID();

}
