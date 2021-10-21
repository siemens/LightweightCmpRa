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
package com.siemens.pki.lightweightcmpra.cryptoservices;

/**
 * This class wraps an exception that could be thrown during the cert validation
 * process.
 *
 *
 */
public class PkiCertVerificationException extends Exception {

    private static final long serialVersionUID = 10L;

    /**
     * Constructor for PkiCertVerificationException
     *
     * @param message
     *            message with the reason why the verification failed
     */
    public PkiCertVerificationException(final String message) {
        super(message);
    }

    /**
     * Constructor for PkiCertVerificationException
     *
     * @param message
     *            message with the reason why the verification failed
     * @param cause
     *            exception occured during verification process
     */
    public PkiCertVerificationException(final String message,
            final Throwable cause) {
        super(message, cause);
    }
}
