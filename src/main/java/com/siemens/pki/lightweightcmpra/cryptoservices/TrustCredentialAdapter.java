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
package com.siemens.pki.lightweightcmpra.cryptoservices;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.JAXB;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.config.xmlparser.TRUSTCREDENTIALS;
import com.siemens.pki.lightweightcmpra.config.xmlparser.TRUSTCREDENTIALS.CrlFile;
import com.siemens.pki.lightweightcmpra.config.xmlparser.TRUSTCREDENTIALS.CrlUrl;
import com.siemens.pki.lightweightcmpra.server.CmpHttpServer;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;
import com.siemens.pki.lightweightcmpra.util.RegexCertMatcher;

/**
 * Class for building a certification chain for given certificate and verifying
 * it. Relies on a set of root CA certificates and intermediate certificates
 * that will be used for building the certification chain. The verification
 * process assumes that all self-signed certificates in the set are trusted root
 * CA certificates and all other certificates in the set are intermediate
 * certificates.
 *
 */

@SuppressWarnings("restriction")
public class TrustCredentialAdapter {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(TrustCredentialAdapter.class);

    /**
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration
     *            file
     *
     * @param peerAuthenticationNeeded
     *            true if additional authentication should be supported
     * @return the created factory
     * @throws Exception
     *             in case of general error
     * @throws PkiCertVerificationException
     *             in case of error during chain building
     * @throws InvalidAlgorithmParameterException
     *             in case if invalid parameters given in algorithms
     * @throws NoSuchAlgorithmException
     *             in case of unsupported algorithms
     * @throws KeyStoreException
     *             in case of error in key store handling
     */
    public static TrustManagerFactory createTrustManagerFactoryFromConfig(
            final TRUSTCREDENTIALS config,
            final boolean peerAuthenticationNeeded) throws Exception,
            PkiCertVerificationException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, KeyStoreException {
        final KeyStore trustStore =
                CertUtility.loadTruststoreFromFile(config.getTrustStorePath(),
                        config.getTrustStorePassword().toCharArray());
        final CertSelector peerMatcher = peerAuthenticationNeeded
                ? new RegexCertMatcher(
                        config.getMatchingPeerCertificateSubject())
                : new X509CertSelector();
        final Date validationDate = new Date();
        final Set<Object> lstCertCrlStores = new HashSet<>();

        if (config.isEnableCrlCheck()) {
            String lastLoadedResource = null;
            try {
                final CertificateFactory cf =
                        CertificateFactory.getInstance("X.509");
                if (config.getCrlFile() != null) {
                    for (final CrlFile crlFile : config.getCrlFile()) {
                        lastLoadedResource = crlFile.getPath();
                        try (InputStream fileInputStream =
                                new BufferedInputStream(
                                        ConfigFileLoader.getConfigFileAsStream(
                                                lastLoadedResource))) {
                            while (fileInputStream.available() > 0) {
                                final X509CRL generateCRL = (X509CRL) cf
                                        .generateCRL(fileInputStream);
                                final Date nextUpdate =
                                        generateCRL.getNextUpdate();
                                if (nextUpdate != null
                                        && nextUpdate.before(validationDate)) {
                                    CmpHttpServer.LOGGER.warn("CRL from "
                                            + crlFile + " needs update");
                                }
                                lstCertCrlStores.add(generateCRL);
                            }
                        }
                    }
                }
                if (config.getCrlUrl() != null) {
                    for (final CrlUrl crlUrl : config.getCrlUrl()) {
                        lastLoadedResource = crlUrl.getUri();
                        try (InputStream urlStream = new BufferedInputStream(
                                new URL(lastLoadedResource).openStream())) {
                            while (urlStream.available() > 0) {
                                final X509CRL generateCRL =
                                        (X509CRL) cf.generateCRL(urlStream);
                                final Date nextUpdate =
                                        generateCRL.getNextUpdate();
                                if (nextUpdate != null
                                        && nextUpdate.before(validationDate)) {
                                    CmpHttpServer.LOGGER.warn("CRL from "
                                            + crlUrl + " needs update");
                                }
                                lstCertCrlStores.add(generateCRL);
                            }
                        }
                    }
                }
            } catch (CertificateException | CRLException | IOException excpt) {
                CmpHttpServer.LOGGER.error("Could not load CRL from "
                        + lastLoadedResource + ": " + excpt.getMessage());
                throw new PkiCertVerificationException("Could not load CRL",
                        excpt);
            }
        }

        final CollectionCertStoreParameters ccsp =
                new CollectionCertStoreParameters(lstCertCrlStores);

        final CertStore store = CertStore.getInstance("Collection", ccsp);

        final CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");

        final PKIXBuilderParameters buildParams =
                new PKIXBuilderParameters(trustStore, peerMatcher);

        // set options for certificate revocation checking
        final EnumSet<PKIXRevocationChecker.Option> colRevCheckerOpts =
                EnumSet.noneOf(PKIXRevocationChecker.Option.class);

        if (config.isEnableOnlyEndEntityCheck()) {
            // check only revocation status of end entity (server)
            // certificate
            colRevCheckerOpts.add(PKIXRevocationChecker.Option.ONLY_END_ENTITY);
        }
        if (config.isEnableSoftFail()) {
            // allow revocation check to succeed if the revocation
            // status cannot be determined
            colRevCheckerOpts.add(PKIXRevocationChecker.Option.SOFT_FAIL);
        }
        if (!config.isEnableOcspCheck() || config.isEnablePreferCRLs()) {
            // prefere CRL revocation status checking to OCSP
            colRevCheckerOpts.add(PKIXRevocationChecker.Option.PREFER_CRLS);
        }
        if (!config.isEnableCrlCheck() || !config.isEnableOcspCheck()
                || config.isEnableNoFallback()) {
            // disable fallback mechanism either OCSP or CRL
            colRevCheckerOpts.add(PKIXRevocationChecker.Option.NO_FALLBACK);
        }
        buildParams.addCertStore(store);

        final PKIXRevocationChecker revChecker =
                (PKIXRevocationChecker) cpb.getRevocationChecker();

        if (config.isEnableOcspCheck()) {
            Security.setProperty("ocsp.enable", "true");
            final String defaultOcspResponder =
                    config.getDefaultOcspResponder();
            if (defaultOcspResponder != null) {
                try {
                    Security.setProperty("ocsp.responderURL",
                            defaultOcspResponder);
                    revChecker.setOcspResponder(new URI(defaultOcspResponder));
                } catch (final URISyntaxException e) {
                    throw new PkiCertVerificationException(
                            "ocspResponderURL(getDefOcspResp) broken", e);
                }
            } else {
                System.getProperties().remove("ocsp.responderURL");
                revChecker.setOcspResponder(null);
            }
        } else {
            Security.setProperty("ocsp.enable", "false");
            System.getProperties().remove("ocsp.responderURL");
            revChecker.setOcspResponder(null);
        }

        if (config.isEnableOcspCheck() || config.isEnableCrlCheck()) {
            // CRL or OCSP revocation checking
            buildParams.setRevocationEnabled(true);
            buildParams.addCertPathChecker(revChecker);

            if (!config.isEnableOcspCheck() && config.isEnableCrlCheck()) {
                if (!colRevCheckerOpts
                        .contains(PKIXRevocationChecker.Option.PREFER_CRLS)) {
                    colRevCheckerOpts
                            .add(PKIXRevocationChecker.Option.PREFER_CRLS);
                }
            }

        } else { // no revocation checking
            buildParams.setRevocationEnabled(false);
        }

        revChecker.setOptions(colRevCheckerOpts);

        if (config.isEnableCRLDistPoints()) {
            System.setProperty("com.sun.security.enableCRLDP", "true");
        } else {
            System.setProperty("com.sun.security.enableCRLDP", "false");
        }
        final TrustManagerFactory tmf = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(new CertPathTrustManagerParameters(buildParams));
        return tmf;
    }

    private final TRUSTCREDENTIALS certVerifyConfig;
    private final Set<TrustAnchor> trust = new HashSet<>();

    private final Set<X509Certificate> intermeditateCertificates =
            new HashSet<>();

    private final RegexCertMatcher peerMatcher;

    /**
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @throws KeyStoreException
     *             in case of errors during keystore handling
     * @throws CertificateException
     *             in case of errors in certificate handling and chain building
     * @throws NoSuchAlgorithmException
     *             in case of unsupported algorithms
     * @throws Exception
     *             in case of general error
     */
    public TrustCredentialAdapter(final TRUSTCREDENTIALS config)
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, Exception {
        this.certVerifyConfig = config;
        peerMatcher = new RegexCertMatcher(
                config.getMatchingPeerCertificateSubject());
        final Date validationDate = new Date();
        final Set<X509Certificate> trustedCertificates =
                CertUtility.loadCertificatesFromKeystore(CertUtility
                        .loadTruststoreFromFile(config.getTrustStorePath(),
                                config.getTrustStorePassword().toCharArray()));
        for (final X509Certificate aktCert : trustedCertificates) {
            if (aktCert.getNotAfter().before(validationDate)) {
                LOGGER.warn(" cert for " + aktCert.getSubjectDN() + ", SN:"
                        + aktCert.getSerialNumber() + " expired");
            }
            if (CertUtility.isSelfSigned(aktCert)) {
                trust.add(new TrustAnchor(aktCert, null));
            } else {
                intermeditateCertificates.add(aktCert);
            }
        }
    }

    /**
     * Attempts to build a certification chain for given certificate and to
     * verify
     * it. Relies on a set of root CA certificates (trust anchors) and a set of
     * intermediate certificates (to be used as part of the chain).
     *
     * @param cert
     *            certificate for validation
     *
     * @param additionalIntermediateCerts
     *            set of intermediate certificates, must also include the
     *            certificate for validation
     *
     * @return the validated chain without trust anchor but with cert
     *
     * @throws PkiCertVerificationException
     *             if the certificate path could not be build and validated
     *             because
     *             of an missing algorithm, provider or a certificate/CRL could
     *             be read
     * @throws Exception
     *             in case of general error
     * @throws PkiCertVerificationException
     *             in case of error during chain building
     * @throws CertificateException
     *             in case if error during certificate handling
     * @throws NoSuchAlgorithmException
     *             in case of unsupported algorithms
     */
    @SuppressWarnings({"unchecked"})
    synchronized public List<? extends X509Certificate> validateCertAgainstTrust(
            final X509Certificate cert,
            final List<X509Certificate> additionalIntermediateCerts)
            throws PkiCertVerificationException, CertificateException,
            NoSuchAlgorithmException, Exception {
        if (!peerMatcher.match(cert)) {
            return null;
        }
        final Date validationDate = new Date();
        final Set<Object> lstCertCrlStores = new HashSet<>();
        for (final X509Certificate aktCert : additionalIntermediateCerts) {
            if (CertUtility.isSelfSigned(aktCert)) {
                LOGGER.warn("intermediate cert for " + aktCert.getSubjectDN()
                        + ", SN:" + aktCert.getSerialNumber()
                        + " is self-signed -> dropped");
                continue;
            }
            if (aktCert.getNotAfter().before(validationDate)) {
                LOGGER.warn("intermediate cert for " + aktCert.getSubjectDN()
                        + ", SN:" + aktCert.getSerialNumber() + " expired");
            }
            lstCertCrlStores.add(aktCert);
        }
        lstCertCrlStores.addAll(intermeditateCertificates);

        if (cert.getNotAfter().before(validationDate)) {
            LOGGER.warn(" cert for " + cert.getSubjectDN() + ", SN:"
                    + cert.getSerialNumber() + " expired");
        }
        lstCertCrlStores.add(cert);

        if (certVerifyConfig.isEnableCrlCheck()) {
            String lastLoadedResource = null;
            try {
                final CertificateFactory cf =
                        CertificateFactory.getInstance("X.509");
                if (certVerifyConfig.getCrlFile() != null) {
                    for (final CrlFile crlFile : certVerifyConfig
                            .getCrlFile()) {
                        lastLoadedResource = crlFile.getPath();
                        try (InputStream inputStream = ConfigFileLoader
                                .getConfigFileAsStream(lastLoadedResource)) {
                            while (inputStream.available() > 0) {
                                final X509CRL generateCRL =
                                        (X509CRL) cf.generateCRL(inputStream);
                                final Date nextUpdate =
                                        generateCRL.getNextUpdate();
                                if (nextUpdate != null
                                        && nextUpdate.before(validationDate)) {
                                    LOGGER.warn("CRL from " + crlFile
                                            + " needs update");
                                }
                                lstCertCrlStores.add(generateCRL);
                            }
                        }
                    }
                }
                if (certVerifyConfig.getCrlUrl() != null) {
                    for (final CrlUrl crlUrl : certVerifyConfig.getCrlUrl()) {
                        lastLoadedResource = crlUrl.getUri();
                        try (InputStream urlStream = new BufferedInputStream(
                                new URL(lastLoadedResource).openStream())) {
                            while (urlStream.available() > 0) {
                                final X509CRL generateCRL =
                                        (X509CRL) cf.generateCRL(urlStream);
                                final Date nextUpdate =
                                        generateCRL.getNextUpdate();
                                if (nextUpdate != null
                                        && nextUpdate.before(validationDate)) {
                                    LOGGER.warn("CRL from " + crlUrl
                                            + " needs update");
                                }
                                lstCertCrlStores.add(generateCRL);
                            }
                        }
                    }
                }
            } catch (CertificateException | CRLException | IOException excpt) {
                LOGGER.error("Could not load CRL from " + lastLoadedResource
                        + ": " + excpt.getMessage());
                throw new PkiCertVerificationException("Could not load CRL",
                        excpt);
            }
        }

        try {
            final CollectionCertStoreParameters ccsp =
                    new CollectionCertStoreParameters(lstCertCrlStores);

            final CertStore store = CertStore.getInstance("Collection", ccsp);

            final CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");

            final X509CertSelector targetConstraints = new X509CertSelector();
            targetConstraints.setCertificate(cert);

            final PKIXBuilderParameters params =
                    new PKIXBuilderParameters(trust, targetConstraints);

            // set options for certificate revocation checking
            final EnumSet<PKIXRevocationChecker.Option> colRevCheckerOpts =
                    EnumSet.noneOf(PKIXRevocationChecker.Option.class);

            if (certVerifyConfig.isEnableOnlyEndEntityCheck()) {
                // check only revocation status of end entity (server)
                // certificate
                colRevCheckerOpts
                        .add(PKIXRevocationChecker.Option.ONLY_END_ENTITY);
            }
            if (certVerifyConfig.isEnableSoftFail()) {
                // allow revocation check to succeed if the revocation
                // status cannot be determined
                colRevCheckerOpts.add(PKIXRevocationChecker.Option.SOFT_FAIL);
            }
            if (!certVerifyConfig.isEnableOcspCheck()
                    || certVerifyConfig.isEnablePreferCRLs()) {
                // prefer CRL revocation status checking to OCSP
                colRevCheckerOpts.add(PKIXRevocationChecker.Option.PREFER_CRLS);
            }
            if (!certVerifyConfig.isEnableCrlCheck()
                    || !certVerifyConfig.isEnableOcspCheck()
                    || certVerifyConfig.isEnableNoFallback()) {
                // disable fallback mechanism either OCSP or CRL
                colRevCheckerOpts.add(PKIXRevocationChecker.Option.NO_FALLBACK);
            }
            params.addCertStore(store);

            final PKIXRevocationChecker revChecker =
                    (PKIXRevocationChecker) cpb.getRevocationChecker();

            if (certVerifyConfig.isEnableOcspCheck()) {
                Security.setProperty("ocsp.enable", "true");
                final String defaultOcspResponder =
                        certVerifyConfig.getDefaultOcspResponder();
                if (defaultOcspResponder != null) {
                    try {
                        Security.setProperty("ocsp.responderURL",
                                defaultOcspResponder);
                        revChecker.setOcspResponder(
                                new URI(defaultOcspResponder));
                    } catch (final URISyntaxException e) {
                        throw new PkiCertVerificationException(
                                "ocspResponderURL(getDefOcspResp) broken", e);
                    }
                } else {
                    System.getProperties().remove("ocsp.responderURL");
                    revChecker.setOcspResponder(null);
                }
            } else {
                Security.setProperty("ocsp.enable", "false");
                System.getProperties().remove("ocsp.responderURL");
                revChecker.setOcspResponder(null);
            }

            if (certVerifyConfig.isEnableOcspCheck()
                    || certVerifyConfig.isEnableCrlCheck()) {
                // CRL or OCSP revocation checking
                params.setRevocationEnabled(true);
                params.addCertPathChecker(revChecker);

                if (!certVerifyConfig.isEnableOcspCheck()
                        && certVerifyConfig.isEnableCrlCheck()) {
                    if (!colRevCheckerOpts.contains(
                            PKIXRevocationChecker.Option.PREFER_CRLS)) {
                        colRevCheckerOpts
                                .add(PKIXRevocationChecker.Option.PREFER_CRLS);
                    }
                }

            } else { // no revocation checking
                params.setRevocationEnabled(false);
            }

            revChecker.setOptions(colRevCheckerOpts);

            if (certVerifyConfig.isEnableCRLDistPoints()) {
                System.setProperty("com.sun.security.enableCRLDP", "true");
            } else {
                System.setProperty("com.sun.security.enableCRLDP", "false");
            }

            final PKIXCertPathBuilderResult result =
                    (PKIXCertPathBuilderResult) cpb.build(params);
            // check validation result according to "Basic Certificate
            // Validation Guideline for Certificate Management"
            final X509Certificate rootCert =
                    result.getTrustAnchor().getTrustedCert();
            final boolean[] rootKeyUsage = rootCert.getKeyUsage();
            if (rootKeyUsage != null && !rootKeyUsage[5]) {
                throw new PkiCertVerificationException(
                        "keyCertSign not set for root certificate "
                                + rootCert.getSubjectX500Principal());
            }
            final List<? extends Certificate> ret =
                    result.getCertPath().getCertificates();
            for (final Certificate certInPath : ret) {
                final X509Certificate x509Certificate =
                        (X509Certificate) certInPath;
                final boolean[] keyUsage = x509Certificate.getKeyUsage();
                if (keyUsage != null) {
                    if (x509Certificate.equals(cert)) {
                        if (!keyUsage[0]) {
                            throw new PkiCertVerificationException(
                                    "digitalSignature not set for certificate "
                                            + x509Certificate
                                                    .getSubjectX500Principal());
                        }
                    } else {
                        if (!keyUsage[5]) {
                            throw new PkiCertVerificationException(
                                    "keyCertSign not set for certificate "
                                            + x509Certificate
                                                    .getSubjectX500Principal());
                        }
                    }
                }
            }
            return (List<? extends X509Certificate>) ret;
        } catch (final CertPathBuilderException certExcpt) {
            //
            // if you would like to debug the PKIX CertPathBuilder
            // add "-Djava.security.debug=certpath" to the command line
            // to get more help, use "-Djava.security.debug=help" (really)
            //
            LOGGER.error("Could not build certificate path: "
                    + certExcpt.getMessage());
            if (LOGGER.isDebugEnabled()) {
                // avoid unnecessary string processing, if debug isn't enabled
                LOGGER.debug("cert :" + cert.getSubjectX500Principal()
                        + ", SN: " + cert.getSerialNumber());
                for (final X509Certificate aktCert : additionalIntermediateCerts) {
                    LOGGER.debug("interm :" + aktCert.getSubjectX500Principal()
                            + ", SN: " + aktCert.getSerialNumber());
                }
                for (final TrustAnchor aktTrust : trust) {
                    LOGGER.debug("trusted :" + aktTrust);
                }
            }
            throw new PkiCertVerificationException(
                    "could not build certificate path", certExcpt);
        } catch (final InvalidAlgorithmParameterException
                | NoSuchAlgorithmException ex) {
            LOGGER.error("Exception while building certificate path:"
                    + ex.getMessage());
            throw new PkiCertVerificationException(
                    "Exception while building certificate path", ex);
        }
    }

}
