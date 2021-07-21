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
package com.siemens.pki.lightweightcmpra.msgvalidation;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;

import com.siemens.pki.lightweightcmpra.msggeneration.PkiMessageGenerator;

/**
 * base of all CMP exceptions
 *
 */
public class BaseCmpException extends RuntimeException {
    private static final long serialVersionUID = 1;
    private final int failInfo;
    private final String errorDetails;

    protected BaseCmpException(final String interfaceName, final Exception ex) {
        super(ex.getMessage() == null ? ex.getCause().toString()
                : ex.getMessage(), ex.getCause() == null ? ex : ex.getCause());
        this.failInfo = PKIFailureInfo.systemFailure;
        this.errorDetails = interfaceName + ": " + ex.getLocalizedMessage();
    }

    /**
     *
     * @param interfaceName
     *            interface name used as prefix message text
     * @param failInfo
     *            CMP failInfo proposed for CMP error message
     * @param errorDetails
     *            description of some details related to the error
     * @param ex
     *            the underlying exception
     */
    protected BaseCmpException(final String interfaceName, final int failInfo,
            final String errorDetails, final Exception ex) {
        super(ex == null || ex.getMessage() == null ? errorDetails
                : ex.getMessage(),
                ex == null || ex.getCause() == null ? ex : ex.getCause());
        this.failInfo = failInfo;
        this.errorDetails = interfaceName + ": " + errorDetails;
    }

    public PKIBody asErrorBody() {
        return PkiMessageGenerator.generateErrorBody(failInfo, errorDetails);
    }

    @Override
    public String toString() {
        return "CmpException [failInfo=" + failInfo + ", errorDetails="
                + errorDetails + "]";
    }

}
