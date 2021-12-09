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

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;

import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;

/**
 * upstream interface for nested message processing
 *
 */
public interface UpstreamNestingFunctionIF {
    UpstreamNestingFunctionIF NO_NESTING = new UpstreamNestingFunctionIF() {

        @Override
        public Function<PKIMessage[], PKIMessage[]> getAsArrayWrappingFunction(
                final Function<PKIMessage, PKIMessage> wrappedFunction) {
            return in -> {
                final PKIMessage[] ret = new PKIMessage[in.length];
                for (int i = 0; i < in.length; i++) {
                    ret[i] = wrappedFunction.apply(in[i]);
                }
                return ret;
            };

        }

        @Override
        public Function<PKIMessage, PKIMessage> getAsWrappingFunction(
                final Function<PKIMessage, PKIMessage> wrappedFunction) {
            return msg -> wrappedFunction.apply(msg);
        }

        @Override
        public PKIMessage[] unwrapResponses(final PKIMessage nestedResponse) {
            return new PKIMessage[] {nestedResponse};
        }

        @Override
        public PKIMessage wrapRequests(final PKIMessage... requests) {
            if (requests.length != 1) {
                throw new UnsupportedOperationException(
                        "only one request supported");
            }
            return requests[0];
        }
    };

    /**
     * return a requests/responses function doing the whole nesting stuff for
     * multiple requests and related responses
     *
     * @param wrappedFunction
     *            function used for forwarding and receiving the nested request
     *            and response
     * @return the processing function
     */
    Function<PKIMessage[], PKIMessage[]> getAsArrayWrappingFunction(
            final Function<PKIMessage, PKIMessage> wrappedFunction);

    /**
     * return a request/response function doing the whole nesting stuff for one
     * request and one related response
     *
     * @param wrappedFunction
     *            function used for processing the nested request and response
     *            for only one request and response
     * @return the processing function
     */
    Function<PKIMessage, PKIMessage> getAsWrappingFunction(
            final Function<PKIMessage, PKIMessage> wrappedFunction);

    /**
     * unwrap a nested response
     *
     * @param nestedResponse
     *            nested {@link PKIMessage} to unwrap
     * @return formerly wrapped messages
     * @throws CmpProcessingException
     *             in case of invalid (type, protection, header) nestedResponse
     */
    PKIMessage[] unwrapResponses(final PKIMessage nestedResponse);

    /**
     *
     * @param requests
     *            requests to wrap in a nested message
     * @return {@link PKIMessage} of Type {@link PKIBody#TYPE_NESTED}
     */
    PKIMessage wrapRequests(final PKIMessage... requests);

}
