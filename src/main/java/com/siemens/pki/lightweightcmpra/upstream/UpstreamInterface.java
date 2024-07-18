/*
 *  Copyright (c) 2022 Siemens AG
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
package com.siemens.pki.lightweightcmpra.upstream;

import java.util.function.BiFunction;

/**
 * generic definitions for all upstream interfaces
 *
 */
public interface UpstreamInterface extends BiFunction<byte[], String, byte[]> {

    interface AsyncResponseHandler {
        void apply(byte[] response) throws Exception;
    }

    /**
     * provide callback for async responses
     *
     * @param asyncResponseHandler
     *            the callback
     */
    void setDelayedResponseHandler(AsyncResponseHandler asyncResponseHandler);

    void stop();
}
