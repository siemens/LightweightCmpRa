/*
 *  Copyright (c) 2021 Siemens AG
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
import com.siemens.pki.lightweightcmpra.main.RA;
import com.siemens.pki.lightweightcmpra.test.framework.TestUtils;
import java.io.File;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestGeneralMessagesWithPolling extends CmpTestcaseBase {

    private static final String UPSTREAM_DIR = "./target/CmpTest/GenUpstream_GEN";
    private static final String DOWNSTREAM_DIR = "./target/CmpTest/GenDownstream_GEN";

    @AfterClass
    public static void cleanUpDirsAnRas() {
        RA.stopAllRas();
        TestUtils.removeDirectories(DOWNSTREAM_DIR, UPSTREAM_DIR);
    }

    @BeforeClass
    public static void setUpDirsAndRas() throws Exception {
        TestUtils.createDirectories(DOWNSTREAM_DIR, UPSTREAM_DIR);
        initTestbed("DelayedSupportMessagesRaTestConfig.yaml", "DelayedSupportMessagesLraTestConfig.yaml");
    }

    @Before
    public void cleanDirectories() {
        TestUtils.deleteAllFilesIn(DOWNSTREAM_DIR, UPSTREAM_DIR);
    }

    /**
     * CRL Update Retrieval
     *
     * @throws Exception
     */
    @Test(timeout = 100000L)
    public void testCrlUpdateRetrieval() throws Exception {
        final String cmdArgs = "--configfile " + "DelayedClientGeneralMessagesWithHttpAndSignature.yaml" + " "
                + "--getCrls ./target/CmpTest/Results/CRLs.crl " + "--issuer CN=distributionPoint ";
        final int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("updated crls", new File("./target/CmpTest/Results/CRLs.crl").length() > 0);
    }

    /**
     * CRL Update Retrieval
     *
     * @throws Exception
     */
    @Test(timeout = 100000L)
    public void testCrlUpdateRetrievalWithOldCrl() throws Exception {
        final String cmdArgs = "--configfile " + "DelayedClientGeneralMessagesWithHttpAndSignature.yaml" + " "
                + "--getCrls ./target/CmpTest/Results/CRLs.crl "
                + "--oldCRL ./src/test/java/com/siemens/pki/lightweightcmpra/test/config/credentials/CRL.der ";
        final int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("updated crls", new File("./target/CmpTest/Results/CRLs.crl").length() > 0);
    }

    /*
     * Get CA certificates
     */
    @Test(timeout = 100000L)
    public void testGetCaCerts() throws Exception {
        final String cmdArgs = "--configfile " + "DelayedClientGeneralMessagesWithHttpAndSignature.yaml" + " "
                + "--getCaCertificates ./target/CmpTest/Results/Certificates.cer ";
        final int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("CA certificates", new File("./target/CmpTest/Results/Certificates.cer").length() > 0);
    }

    /*
     * Get certificate request template
     */
    @Test(timeout = 100000L)
    public void testGetCertificateRequestTemplate() throws Exception {

        final String cmdArgs = "--configfile " + "DelayedClientGeneralMessagesWithHttpAndSignature.yaml" + " "
                + "--getCertificateRequestTemplate ./target/CmpTest/Results/Template.der ";
        final int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("template", new File("./target/CmpTest/Results/Template.der").length() > 0);
    }

    /*
     * Get root CA certificate update
     */
    @Test(timeout = 100000L)
    public void testGetRootCaKeyUpdateInfo() throws Exception {
        final String cmdArgs = "--configfile " + "DelayedClientGeneralMessagesWithHttpAndSignature.yaml" + " "
                + "--getRootCaCertificateUpdate " + "--NewWithNew ./target/CmpTest/Results/NewWithNew.cer "
                + "--NewWithOld ./target/CmpTest/Results/NewWithOld.cer "
                + "--OldWithNew ./target/CmpTest/Results/OldWithNew.cer ";
        final int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("NewWithNew", new File("./target/CmpTest/Results/NewWithNew.cer").length() > 0);
        assertTrue("NewWithOld", new File("./target/CmpTest/Results/NewWithOld.cer").length() > 0);
        assertTrue("OldWithNew", new File("./target/CmpTest/Results/OldWithNew.cer").length() > 0);
    }
}
