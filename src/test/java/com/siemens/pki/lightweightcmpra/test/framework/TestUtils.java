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
package com.siemens.pki.lightweightcmpra.test.framework;

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.siemens.pki.cmpracomponent.protection.PBMAC1Protection;
import com.siemens.pki.cmpracomponent.protection.PasswordBasedMacProtection;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.protection.SignatureBasedProtection;
import com.siemens.pki.lightweightcmpra.configuration.SharedSecretCredentialContextImpl;
import com.siemens.pki.lightweightcmpra.configuration.SignatureCredentialContextImpl;
import com.siemens.pki.lightweightcmpra.configuration.VerificationContextImpl;
import com.siemens.pki.lightweightcmpra.upstream.online.CmpHttpClient;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.SecureRandom;
import java.util.function.Function;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.elements.exception.ConnectorException;

/**
 *
 *
 */
public class TestUtils {

    private static final String PASSWORD = "Password";

    static final SecureRandom RANDOM = new SecureRandom();

    private static final char[] PASSWORD_AS_CHAR_ARRAY = getPassword().toCharArray();

    private static final String INTERFACE_NAME = "TEST_CLIENT";

    /**
     * create a HTTP CMP client
     *
     * @param serverPath
     *            server URL to contact
     * @return
     * @throws Exception
     */
    public static Function<PKIMessage, PKIMessage> createCmpClient(final String serverPath) throws Exception {
        if (serverPath.toLowerCase().startsWith("http")) {
            final CmpHttpClient cmpHttpClient = new CmpHttpClient(new URL(serverPath), 100);
            return request -> {
                try {
                    return ifNotNull(cmpHttpClient.apply(request.getEncoded(), "http client"), PKIMessage::getInstance);
                } catch (RuntimeException | IOException e) {
                    fail(e.getMessage());
                    return null;
                }
            };
        }
        if (serverPath.toLowerCase().startsWith("coap")) {
            final CoapClient client = new CoapClient(serverPath);
            return msg -> {
                try {
                    return ifNotNull(
                            client.post(msg.getEncoded(), MediaTypeRegistry.APPLICATION_OCTET_STREAM)
                                    .getPayload(),
                            PKIMessage::getInstance);
                } catch (RuntimeException | ConnectorException | IOException e) {
                    fail(e.toString());
                    return null;
                }
            };
        }
        throw new IllegalArgumentException("invalid server path: " + serverPath);
    }

    public static void createDirectories(String... directoryNames) {
        for (final String akt : directoryNames) {
            final File dirFile = new File(akt);
            if (dirFile.exists()) {
                deleteDirectory(dirFile);
            }
            assertTrue("creating " + akt, dirFile.mkdirs());
        }
    }

    public static PasswordBasedMacProtection createPasswordBasedMacProtection(
            final String keyId, final String sharedSecret) throws Exception {
        final SharedSecretCredentialContextImpl config = new SharedSecretCredentialContextImpl();
        config.setSenderKID(keyId.getBytes());
        config.setSharedSecret(sharedSecret.getBytes());
        config.setPrf("SHA256");
        config.setMacAlgorithm("SHA256");
        return new PasswordBasedMacProtection(config, INTERFACE_NAME);
    }

    public static ProtectionProvider createPasswordBasedMacProtection(
            final String keyId,
            final String sharedSecret,
            final ASN1ObjectIdentifier owf,
            final ASN1ObjectIdentifier mac)
            throws Exception {
        final SharedSecretCredentialContextImpl config = new SharedSecretCredentialContextImpl();
        config.setSenderKID(keyId.getBytes());
        config.setSharedSecret(sharedSecret.getBytes());
        config.setPrf(owf.getId());
        config.setMacAlgorithm(mac.getId());
        return new PasswordBasedMacProtection(config, INTERFACE_NAME);
    }

    public static ProtectionProvider createPBMAC1Protection(
            final String keyId, final String sharedSecret, final AlgorithmIdentifier prf, final AlgorithmIdentifier mac)
            throws Exception {
        final SharedSecretCredentialContextImpl config = new SharedSecretCredentialContextImpl();
        config.setSenderKID(keyId.getBytes());
        config.setSharedSecret(sharedSecret.getBytes());
        config.setPrf(prf.getAlgorithm().getId());
        config.setMacAlgorithm(mac.getAlgorithm().getId());
        return new PBMAC1Protection(config, INTERFACE_NAME);
    }

    public static SignatureBasedProtection createSignatureBasedProtection(
            final String fileName, final char[] password) {
        final SignatureCredentialContextImpl config = new SignatureCredentialContextImpl();
        config.setKeyStore(ConfigFileLoader.getConfigFileAsUri(fileName));
        config.setPassword(new String(password).getBytes());
        return new SignatureBasedProtection(config, INTERFACE_NAME);
    }

    public static VerificationContextImpl createVerificationContext(final String fileName) throws URISyntaxException {
        final VerificationContextImpl verifierConfig = new VerificationContextImpl();
        verifierConfig.setTrustedCertificates(new URI[] {new URI(fileName)});
        return verifierConfig;
    }

    private static void deleteAllFilesIn(final File directory) {
        final File[] allContents = directory.listFiles();
        if (allContents != null) {
            for (final File file : allContents) {
                deleteDirectory(file);
            }
        }
    }

    public static void deleteAllFilesIn(String... directoryNames) {
        for (final String akt : directoryNames) {
            deleteAllFilesIn(new File(akt));
        }
    }

    private static void deleteDirectory(final File directoryToBeDeleted) {
        deleteAllFilesIn(directoryToBeDeleted);
        assertTrue("delete " + directoryToBeDeleted, directoryToBeDeleted.delete());
    }

    public static String getPassword() {
        return PASSWORD;
    }

    public static char[] getPasswordAsCharArray() {
        return PASSWORD_AS_CHAR_ARRAY;
    }

    public static void removeDirectories(String... directoryNames) {
        for (final String akt : directoryNames) {
            deleteDirectory(new File(akt));
        }
    }

    // utility class, never create an instance
    private TestUtils() {}
}
