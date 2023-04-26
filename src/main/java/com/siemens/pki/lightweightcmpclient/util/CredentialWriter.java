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
package com.siemens.pki.lightweightcmpclient.util;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.util.Base64.Encoder;

/**
 * utility class to save various credentials, certificates and CRLs
 *
 */
public class CredentialWriter {

    private static final Encoder MIME_ENCODER = java.util.Base64.getMimeEncoder(64, new byte[] {'\r', '\n'});

    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERT = "-----END CERTIFICATE-----";

    private static final String BEGIN_CRL = "-----BEGIN X509 CRL-----";
    private static final String END_CRL = "-----END X509 CRL-----";

    private static final String BEGIN_PUB_KEY = "-----BEGIN PUBLIC KEY-----";
    private static final String END_PUB_KEY = "-----END PUBLIC KEY-----";

    private static final String BEGIN_PRIV_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_PRIV_KEY = "-----END PRIVATE KEY-----";

    /**
     * write a certificate in PEM format
     *
     * @param cert
     *            certificate to write
     * @param out
     *            stream to write to
     * @throws CertificateEncodingException
     *             in case of error
     */
    public static void writeCert(final Certificate cert, final OutputStream out) throws CertificateEncodingException {
        writePem(BEGIN_CERT, END_CERT, cert.getEncoded(), out);
    }

    /**
     * write a crl in PEM format
     *
     * @param crl
     *            CRL to write
     * @param out
     *            stream to write to
     * @throws CRLException
     *             in case of error
     */
    public static void writeCrl(final X509CRL crl, final OutputStream out) throws CRLException {
        writePem(BEGIN_CRL, END_CRL, crl.getEncoded(), out);
    }

    /**
     * write a PKCS12 keystore
     *
     * @param chain
     *            certificate chain to write
     * @param key
     *            private key to write
     * @param password
     *            protection password
     * @param out
     *            stream to write to
     * @throws KeyStoreException
     *             in case of
     * @throws GeneralSecurityException
     *             in case of error
     * @throws IOException
     *             in case of error
     */
    public static void writeKeystore(
            final Certificate[] chain, final PrivateKey key, final char[] password, final OutputStream out)
            throws GeneralSecurityException, IOException {
        final KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, password);
        ks.setKeyEntry("cert", key, password, chain);
        ks.store(out, password);
    }

    /**
     * write a private key in PEM format
     *
     * @param key
     *            private key to write
     * @param out
     *            stream to write to
     */
    public static void writePrivateKey(final PrivateKey key, final OutputStream out) {
        writePem(BEGIN_PRIV_KEY, END_PRIV_KEY, key.getEncoded(), out);
    }

    /**
     * write a public key in PEM format
     *
     * @param key
     *            public key to write
     * @param out
     *            stream to write to
     */
    public static void writePublicKey(final PublicKey key, final OutputStream out) {
        writePem(BEGIN_PUB_KEY, END_PUB_KEY, key.getEncoded(), out);
    }

    private static void writePem(
            final String pemBegin, final String pemEnd, final byte[] encoded, final OutputStream out) {
        final PrintStream prout = new PrintStream(out, false);
        prout.println(pemBegin);
        prout.println(MIME_ENCODER.encodeToString(encoded));
        prout.println(pemEnd);
        prout.flush();
    }
}
