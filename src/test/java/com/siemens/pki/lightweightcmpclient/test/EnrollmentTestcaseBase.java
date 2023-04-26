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
import com.siemens.pki.lightweightcmpra.test.framework.CmpCaMock;
import com.siemens.pki.lightweightcmpra.test.framework.TestUtils;
import com.siemens.pki.lightweightcmpra.util.CredentialLoader;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

public class EnrollmentTestcaseBase extends CmpTestcaseBase {

    public void enrollWithConfig(String configFile) throws IOException, GeneralSecurityException {
        String cmdArgs = "--configfile " + configFile + " " + "--enroll ./target/CmpTest/Results/EnrollmentResult.pem "
                + "--enrollmentChain ./target/CmpTest/Results/EnrollmentChain.pem ";
        int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("enrollment result", new File("./target/CmpTest/Results/EnrollmentResult.pem").length() > 0);
        assertTrue("enrollment chain", new File("./target/CmpTest/Results/EnrollmentChain.pem").length() > 0);
    }

    public void enrollWithConfigAndCertProfile(String configFile, String certProfile)
            throws IOException, GeneralSecurityException {
        String cmdArgs = "--configfile " + configFile + " " + "--enroll ./target/CmpTest/Results/EnrollmentResult.pem "
                + "--enrollmentChain ./target/CmpTest/Results/EnrollmentChain.pem " + "--certProfile " + certProfile
                + " ";
        int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("enrollment result", new File("./target/CmpTest/Results/EnrollmentResult.pem").length() > 0);
        assertTrue("enrollment chain", new File("./target/CmpTest/Results/EnrollmentChain.pem").length() > 0);
    }

    public void revokeWithConfigAndCert(String configFile) throws IOException, GeneralSecurityException {
        String cmdArgs = "--configfile " + configFile + " " + "--enroll ./target/CmpTest/Results/EnrollmentResult.pem "
                + "--enrollmentChain ./target/CmpTest/Results/EnrollmentChain.pem "
                + "--enrollmentKeystore ./target/CmpTest/Results/EnrollmentKeystore.p12 "
                + "--enrollmentKeystorePassword secret";
        int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("enrollment result", new File("./target/CmpTest/Results/EnrollmentResult.pem").length() > 0);
        assertTrue("enrollment chain", new File("./target/CmpTest/Results/EnrollmentChain.pem").length() > 0);

        cmdArgs = "--configfile " + configFile + " " + "--revokecert ./target/CmpTest/Results/EnrollmentResult.pem ";
        ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
    }

    public void revokeWithIssuerAndSerial(String configFile) throws IOException, GeneralSecurityException {
        String cmdArgs = "--configfile " + configFile + " " + "--enroll ./target/CmpTest/Results/EnrollmentResult.pem "
                + "--enrollmentChain ./target/CmpTest/Results/EnrollmentChain.pem "
                + "--enrollmentKeystore ./target/CmpTest/Results/EnrollmentKeystore.p12 "
                + "--enrollmentKeystorePassword secret";
        int ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
        assertTrue("enrollment result", new File("./target/CmpTest/Results/EnrollmentResult.pem").length() > 0);
        assertTrue("enrollment chain", new File("./target/CmpTest/Results/EnrollmentChain.pem").length() > 0);
        X509Certificate certToRevoke = CredentialLoader.loadCertificates(
                        new File("./target/CmpTest/Results/EnrollmentResult.pem").toURI())
                .get(0);
        cmdArgs = "--configfile " + configFile + " " + "--revoke " + "--issuer "
                + certToRevoke.getIssuerX500Principal().getName() + " --serial " + certToRevoke.getSerialNumber();
        ret = CliCmpClient.runClient(cmdArgs.split("\\s+"));
        assertEquals("Client failed", 0, ret);
    }

    @Before
    public void setUp() throws Exception {
        new File("./target/CmpTest/Results").mkdirs();
    }

    @After
    public void shutDown() throws Exception {
        TestUtils.deleteDirectory(new File("./target/CmpTest/Results"));
    }

    @BeforeClass
    public static void setUpClass() throws InterruptedException {
        CmpCaMock.launchSingleCaMock();
    }

    @AfterClass
    public static void shutDownClass() {
        CmpCaMock.stopSingleCaMock();
    }
}
