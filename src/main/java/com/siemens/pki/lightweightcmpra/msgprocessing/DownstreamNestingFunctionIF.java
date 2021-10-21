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

import java.util.function.Function;

import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * downstream interface for nested message processing
 *
 */
public interface DownstreamNestingFunctionIF
        extends Function<PKIMessage, PKIMessage> {

    static DownstreamNestingFunctionIF get_NO_NESTING(
            final Function<PKIMessage, PKIMessage> wrappedFunction) {
        return msg -> wrappedFunction.apply(msg);
    }

    /**
     * process a incoming request from downstream and respond a message
     *
     * @param msg
     *            incoming message received from downstream interface
     * @return response message
     */
    @Override
    PKIMessage apply(final PKIMessage msg);

}
