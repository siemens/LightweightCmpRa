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

import com.siemens.pki.lightweightcmpra.main.RA;
import com.siemens.pki.lightweightcmpra.test.framework.CertUtility;
import com.siemens.pki.lightweightcmpra.test.framework.TestUtils;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;
import java.io.File;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;

public class CmpTestcaseBase {

    public static final String RESULT_DIR = "./target/CmpTest/Results";
    public static final File CONFIG_DIRECTORY =
            new File("./src/test/java/com/siemens/pki/lightweightcmpra/test/config");

    protected static void initTestbed(final String... namesOfRaConfigFile)
            throws Exception, GeneralSecurityException, InterruptedException {
        for (final String nameOfRaConfigFile : namesOfRaConfigFile) {
            RA.main(new String[] {nameOfRaConfigFile});
        }
    }

    @AfterClass
    public static void removeResultDir() {
        TestUtils.removeDirectories(RESULT_DIR);
    }

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        Security.addProvider(CertUtility.BOUNCY_CASTLE_PROVIDER);
        ConfigFileLoader.setConfigFileBase(CONFIG_DIRECTORY);
        TestUtils.createDirectories(RESULT_DIR);
    }

    @After
    public void cleanResultDir() {
        TestUtils.deleteAllFilesIn(RESULT_DIR);
    }
}
