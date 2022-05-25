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
package com.siemens.pki.lightweightcmpra.test;

import java.net.HttpURLConnection;
import java.net.URL;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class TestRestRevocation extends EnrollmentTestcaseBase {
    @Before
    public void setUp() throws Exception {
        initTestbed(null, "RestTestConfig.xml");
    }

    /**
     * Revoking certificates on behalf of another's entities
     *
     * @throws Exception
     */
    @Ignore("not implemented anymore")
    @Test
    public void testRevocationOnBehalfOfAnotherEntity() throws Exception {
        final URL clientURL = new URL(
                "http://localhost:6015/revocation?issuer=CN=MyEndEntityId,C=DE&serial=0xABCDEF1234567890");
        final HttpURLConnection httpConnection =
                (HttpURLConnection) clientURL.openConnection();
        httpConnection.setDoInput(true);
        httpConnection.setDoOutput(true);
        httpConnection.setConnectTimeout(30000);
        httpConnection.setReadTimeout(30000);
        httpConnection.setRequestMethod("DELETE");
        httpConnection.connect();
        final int lastResponseCode = httpConnection.getResponseCode();
        Assert.assertEquals("HTTP status", HttpURLConnection.HTTP_OK,
                lastResponseCode);
    }

}
