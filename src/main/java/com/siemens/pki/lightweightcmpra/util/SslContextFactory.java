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
package com.siemens.pki.lightweightcmpra.util;

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.PKIXRevocationChecker.Option;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * factory for {@link SSLContext}
 *
 */
public class SslContextFactory {

    // private static final BouncyCastleProvider PROVIDER = CertUtility.getBouncyCastleProvider();
    private static final String PROVIDER = "SUN";
    private static final Logger LOGGER = LoggerFactory.getLogger(SslContextFactory.class);

    protected static KeyManagerFactory createKeyManagerFactory(
            final URI ownKeyStoreUri, final byte[] ownKeyStorePassword)
            throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        KeyManagerFactory kmf = null;
        if (ownKeyStorePassword != null && ownKeyStoreUri != null) {
            final char[] passwordAsChars = AlgorithmHelper.convertSharedSecretToPassword(ownKeyStorePassword);
            final KeyStore ownKeyStore = CredentialLoader.loadKeyStore(ownKeyStoreUri, passwordAsChars);

            kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ownKeyStore, passwordAsChars);
        }
        return kmf;
    }

    public static SSLContext createSslContext(
            final VerificationContext verificationContext, final URI ownKeyStoreUri, final byte[] ownKeyStorePassword)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyManagementException,
                    UnrecoverableKeyException, KeyStoreException, NoSuchProviderException {

        final TrustManager[] trustManagers = createTrustManagerFactory(verificationContext);

        final KeyManagerFactory kmf = createKeyManagerFactory(ownKeyStoreUri, ownKeyStorePassword);

        // Supports RFC 8446: TLS version 1.3; may support other SSL/TLS versions
        final SSLContext sslContext = SSLContext.getInstance("TLSv1.3");

        sslContext.init(ifNotNull(kmf, KeyManagerFactory::getKeyManagers), trustManagers, new SecureRandom());
        return sslContext;
    }

    protected static TrustManager[] createTrustManagerFactory(final VerificationContext verificationContext)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        TrustManagerFactory tmf = null;
        if (verificationContext != null && verificationContext.getTrustedCertificates() != null) {

            final Collection<X509Certificate> trustedCertificates = verificationContext.getTrustedCertificates();
            if (LOGGER.isDebugEnabled()) {
                for (final X509Certificate aktCert : trustedCertificates) {
                    LOGGER.debug(
                            "trust: " + aktCert.getSubjectX500Principal() + ", I: " + aktCert.getIssuerX500Principal());
                }
            }

            // initial state
            java.security.Security.setProperty("ocsp.enable", "false");
            boolean revocationEnabled = false;

            if (verificationContext.isAIAsEnabled()) {
                revocationEnabled = true;
                java.security.Security.setProperty("ocsp.enable", "true");
                System.setProperty("com.sun.security.enableAIAcaIssuers", "true");
            } else {
                System.setProperty("com.sun.security.enableAIAcaIssuers", "false");
            }

            if (verificationContext.isCDPsEnabled()) {
                revocationEnabled = true;
                System.setProperty("com.sun.security.enableCRLDP", "true");
            } else {
                System.setProperty("com.sun.security.enableCRLDP", "false");
            }

            final Set<Object> lstCertCrlStores = new HashSet<>();

            lstCertCrlStores.addAll(verificationContext.getAdditionalCerts());

            final Collection<X509CRL> crls = verificationContext.getCRLs();
            if (crls != null && !crls.isEmpty()) {
                revocationEnabled = true;
                lstCertCrlStores.add(crls);
            }

            final CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(lstCertCrlStores);

            final CertStore store = CertStore.getInstance("Collection", ccsp, PROVIDER);

            final Set<TrustAnchor> trust = trustedCertificates.stream()
                    .map(trustedCert -> new TrustAnchor(trustedCert, null))
                    .collect(Collectors.toSet());

            final PKIXBuilderParameters params = new PKIXBuilderParameters(trust, new X509CertSelector());

            params.addCertStore(store);

            final CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", PROVIDER);

            final PKIXRevocationChecker revChecker = (PKIXRevocationChecker) cpb.getRevocationChecker();

            final EnumSet<Option> pkixRevocationCheckerOptions = verificationContext.getPKIXRevocationCheckerOptions();
            if (pkixRevocationCheckerOptions != null) {
                revChecker.setOptions(pkixRevocationCheckerOptions);
            }

            final URI ocspResponder = verificationContext.getOCSPResponder();
            if (ocspResponder != null) {
                revocationEnabled = true;
                java.security.Security.setProperty("ocsp.enable", "true");
                revChecker.setOcspResponder(ocspResponder);
            }
            if (revocationEnabled) {
                params.addCertPathChecker(revChecker);
            }
            params.setRevocationEnabled(revocationEnabled);

            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

            tmf.init(new CertPathTrustManagerParameters(params));
            return tmf.getTrustManagers();
        }
        return new X509TrustManager[] {
            new X509TrustManager() {

                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }
        };
    }

    private SslContextFactory() {}
}
