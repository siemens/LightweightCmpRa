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
package com.siemens.pki.lightweightcmpclient.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.siemens.pki.lightweightcmpclient.main.CliCmpClient;
import com.siemens.pki.lightweightcmpra.test.framework.TestUtils;
import java.io.File;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class TestGeneralMessages extends CmpTestcaseBase {

    @Before
    public void setUp() throws Exception {
        new File("./target/CmpTest/Results").mkdirs();
        initTestbed("SupportMessagesTestConfig.yaml");
    }

    @After
    public void shutDown() throws Exception {
        TestUtils.deleteDirectory(new File("./target/CmpTest/Results"));
    }

    /**
     * CRL Update Retrieval
     *
     * @throws Exception
     */
    @Test
    public void testCrlUpdateRetrieval() throws Exception {
        String cmdArgs = "--configfile " + "ClientGeneralMessagesWithHttpAndSignature.yaml" + " "
                + "--getCrls ./target/CmpTest/Results/CRLs.crl " + "--issuer CN=distributionPoint ";
        int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("updated crls", new File("./target/CmpTest/Results/CRLs.crl").length() > 0);
    }

    /**
     * CRL Update Retrieval
     *
     * @throws Exception
     */
    @Test
    public void testCrlUpdateRetrievalWithOldCrl() throws Exception {
        String cmdArgs = "--configfile " + "ClientGeneralMessagesWithHttpAndSignature.yaml" + " "
                + "--getCrls ./target/CmpTest/Results/CRLs.crl "
                + "--oldCRL ./src/test/java/com/siemens/pki/lightweightcmpra/test/config/credentials/CRL.der ";
        int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("updated crls", new File("./target/CmpTest/Results/CRLs.crl").length() > 0);
    }

    /*
     * Get CA certificates
     */
    @Test
    public void testGetCaCerts() throws Exception {
        String cmdArgs = "--configfile " + "ClientGeneralMessagesWithHttpAndSignature.yaml" + " "
                + "--getCaCertificates ./target/CmpTest/Results/Certificates.cer ";
        int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("CA certificates", new File("./target/CmpTest/Results/Certificates.cer").length() > 0);
    }

    /*
     * Get certificate request template
     */
    @Test
    public void testGetCertificateRequestTemplate() throws Exception {

        String cmdArgs = "--configfile " + "ClientGeneralMessagesWithHttpAndSignature.yaml" + " "
                + "--getCertificateRequestTemplate ./target/CmpTest/Results/Template.der ";
        int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("template", new File("./target/CmpTest/Results/Template.der").length() > 0);
    }

    /*
     * Get root CA certificate update
     */
    @Test
    public void testGetRootCaKeyUpdateInfo() throws Exception {
        String cmdArgs = "--configfile " + "ClientGeneralMessagesWithHttpAndSignature.yaml" + " "
                + "--getRootCaCertificateUpdate " + "--NewWithNew ./target/CmpTest/Results/NewWithNew.cer "
                + "--NewWithOld ./target/CmpTest/Results/NewWithOld.cer "
                + "--OldWithNew ./target/CmpTest/Results/OldWithNew.cer ";
        int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("NewWithNew", new File("./target/CmpTest/Results/NewWithNew.cer").length() > 0);
        assertTrue("NewWithOld", new File("./target/CmpTest/Results/NewWithOld.cer").length() > 0);
        assertTrue("OldWithNew", new File("./target/CmpTest/Results/OldWithNew.cer").length() > 0);
    }
}
