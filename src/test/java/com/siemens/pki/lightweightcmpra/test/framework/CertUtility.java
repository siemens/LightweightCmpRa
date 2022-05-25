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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;

/**
 * A utility class for certificate handling
 */
public class CertUtility {

    static private CertificateFactory certificateFactory;
    private static final Logger LOGGER =
            LoggerFactory.getLogger(CertUtility.class);

    private static final SecureRandom RANDOM = new SecureRandom();

    public static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER =
            new BouncyCastleProvider();

    /**
     * conversion function from CMPCertificate to X509 certificate
     *
     * @param cert
     *            certificate to convert
     *
     * @return converted certificate
     *
     * @throws CertificateException
     *             if certificate could not be converted from CMP Certificate
     */
    static public X509Certificate certificateFromCmpCertificate(
            final CMPCertificate cert) throws Exception {
        try {
            return certificateFromEncoded(cert.getEncoded(ASN1Encoding.DER));
        } catch (final IOException excpt) {
            throw new CertificateException(excpt);
        }
    }

    /**
     * conversion function from byte to X509 certificate
     *
     * @param encoded
     *            byte string to encode
     *
     * @return converted certificate
     *
     * @throws CertificateException
     *             if certificate could not be converted from encoded
     */
    public static X509Certificate certificateFromEncoded(final byte[] encoded)
            throws Exception {
        return (X509Certificate) getCertificateFactory()
                .generateCertificate(new ByteArrayInputStream(encoded));
    }

    /**
     * conversion function from X509 certificate to CMPCertificate
     *
     * @param cert
     *            certificate to convert
     *
     * @return converted certificate
     *
     * @throws CertificateException
     *             if certificate could not be converted from CMP Certificate
     */
    static public CMPCertificate cmpCertificateFromCertificate(
            final Certificate cert) throws CertificateException {
        return CMPCertificate.getInstance(cert.getEncoded());
    }

    /**
     * fetch the SubjectKeyIdentifier from a cert
     *
     * @param cert
     *            cert to fetch the SubjectKeyIdentifier
     *
     * @return the SubjectKeyIdentifier encoded as DEROctetString
     */
    public static DEROctetString extractSubjectKeyIdentifierFromCert(
            final X509Certificate cert) {
        final byte[] extensionValueAsDerEncodedOctetString =
                cert.getExtensionValue(
                        org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier
                                .getId());
        if (extensionValueAsDerEncodedOctetString == null) {
            return null;
        }
        final ASN1OctetString extensionValueAsOctetString = ASN1OctetString
                .getInstance(extensionValueAsDerEncodedOctetString);
        return new DEROctetString(ASN1OctetString
                .getInstance(extensionValueAsOctetString.getOctets())
                .getOctets());

    }

    /**
     * generate a new randomly filled byte array
     *
     * @param length
     *            size of byte array to return
     * @return a new randomly filled byte array
     */
    public static byte[] generateRandomBytes(final int length) {
        final byte[] ret = new byte[length];
        RANDOM.nextBytes(ret);
        return ret;
    }

    /**
     * Function to retrieve the static certificate factory object
     *
     * @return static certificate factory object
     *
     * @throws CertificateException
     *             thrown if the certificate factory could not be instantiated
     * @throws Exception
     *             in case of an error
     */
    public static synchronized CertificateFactory getCertificateFactory()
            throws Exception {
        if (certificateFactory == null) {
            certificateFactory = CertificateFactory.getInstance("X.509",
                    BOUNCY_CASTLE_PROVIDER);
        }
        return certificateFactory;
    }

    /**
     * Checks whether given X.509 certificate is self-signed.
     *
     * @param cert
     *            certificate to be checked
     *
     * @return <code>true</code> if the certificate is self-signed
     *
     * @throws CertificateException
     *             if the certificate could not be parsed
     * @throws NoSuchAlgorithmException
     *             if the public key could not be extracted from the certificate
     * @throws NoSuchProviderException
     *             if the public key could not be extracted from the certificate
     */
    public static boolean isSelfSigned(final X509Certificate cert)
            throws CertificateException, NoSuchAlgorithmException,
            NoSuchProviderException {
        try {
            // Try to verify certificate signature with its own public key
            final PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (final SignatureException | InvalidKeyException keyEx) {
            // Invalid key --> not self-signed
            return false;
        }
    }

    /**
     * Load a certificates form a file.
     *
     * @param filename
     *            name of the file to load from
     *
     * @return all found certificates
     *
     * @throws CertificateException
     *             if the certificate could not be parsed
     * @throws Exception
     *             if the certificate file could not be loaded
     */
    public static synchronized List<X509Certificate> loadCertificatesFromFile(
            final String filename) throws Exception {
        try (InputStream is =
                ConfigFileLoader.getConfigFileAsStream(filename)) {
            final List<X509Certificate> ret = new ArrayList<>();
            final CertificateFactory cf = getCertificateFactory();
            for (final Certificate aktCert : cf.generateCertificates(is)) {
                ret.add((X509Certificate) aktCert);
            }
            return ret;
        } catch (final IOException ex) {
            LOGGER.error("failing to load certificates from " + filename, ex);
            throw ex;
        }
    }

    /**
     * Load key store (JKS or PKCS #12) from the specified file.
     *
     * @param filename
     *            name of the key store file
     * @param password
     *            key store password
     *
     * @return key store
     *
     * @throws KeyStoreException
     *             if key store could not be loaded from file
     */
    public static KeyStore loadKeystoreFromFile(final String filename,
            final char[] password) throws KeyStoreException {
        KeyStore ks;
        try {
            // guessing type of keystore
            if (filename.toLowerCase(Locale.getDefault()).endsWith(".p12")) {
                try (InputStream in =
                        ConfigFileLoader.getConfigFileAsStream(filename)) {
                    ks = loadKeystoreFromStream("PKCS12", in, password);
                } catch (final KeyStoreException ex) {
                    try (InputStream in =
                            ConfigFileLoader.getConfigFileAsStream(filename)) {
                        ks = loadKeystoreFromStream("JKS", in, password);
                    }
                }
            } else {
                try (InputStream in =
                        ConfigFileLoader.getConfigFileAsStream(filename)) {
                    ks = loadKeystoreFromStream("JKS", in, password);
                } catch (final KeyStoreException ex) {
                    try (InputStream in =
                            ConfigFileLoader.getConfigFileAsStream(filename)) {
                        ks = loadKeystoreFromStream("PKCS12", in, password);
                    }
                }
            }
            return ks;
        } catch (

        final IOException excpt) {
            throw new KeyStoreException(excpt);
        }
    }

    /**
     * Load key store (JKS or PKCS #12) from the specified file.
     *
     * @param keyStoreType
     *            type of key store, either "JKS" or "PKCS12"
     * @param is
     *            input stream of the key store file
     * @param password
     *            key store password
     *
     * @return key store
     *
     * @throws KeyStoreException
     *             if key store could not be loaded from file
     */
    private static KeyStore loadKeystoreFromStream(final String keyStoreType,
            final InputStream is, final char[] password)
            throws KeyStoreException {
        try {
            final KeyStore ks = KeyStore.getInstance(keyStoreType);
            ks.load(is, password);
            return ks;
        } catch (IOException | CertificateException
                | NoSuchAlgorithmException excpt) {
            throw new KeyStoreException(excpt);
        }
    }

}
