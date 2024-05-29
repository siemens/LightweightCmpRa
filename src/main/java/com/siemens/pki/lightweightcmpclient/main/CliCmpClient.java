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
package com.siemens.pki.lightweightcmpclient.main;

import com.siemens.pki.cmpclientcomponent.main.CmpClient;
import com.siemens.pki.cmpracomponent.configuration.GetRootCaCertificateUpdateHandler.RootCaCertificateUpdateResponse;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.lightweightcmpclient.configuration.ClientConfiguration;
import com.siemens.pki.lightweightcmpclient.configuration.ClientContextImpl;
import com.siemens.pki.lightweightcmpclient.configuration.RevocationContextImpl;
import com.siemens.pki.lightweightcmpclient.util.CredentialWriter;
import com.siemens.pki.lightweightcmpra.configuration.YamlConfigLoader;
import com.siemens.pki.lightweightcmpra.upstream.UpstreamInterface;
import com.siemens.pki.lightweightcmpra.upstream.UpstreamInterfaceFactory;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;
import com.siemens.pki.lightweightcmpra.util.CredentialLoader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.asn1.cmp.PKIBody;

public class CliCmpClient {

    private static final String PREFIX_APPENDIX = ". This option can be used in conjunction with the -";

    private static final String DATE_FORMAT = "yyyy-MM-dd";

    private static final DateFormat DATE_PARSER = new SimpleDateFormat(DATE_FORMAT);

    private static final Option OPTION_configfile = new Option(
            "c",
            "configfile",
            true,
            "<arg> is the path and name of the CMP client configuration file to use; this option is mandatory.");

    private static final Option OPTION_certProfile =
            new Option("p", "certProfile", true, "certProfile to use; optional for all client commands");

    private static final Option OPTION_help = new Option("h", "help", false, "print help and exit.");

    private static final Option OPTION_configroot = new Option(
            "C",
            "configroot",
            true,
            "configuration root path, used to resolve relative CMP client configuration file path and pathes given in the configuration file");

    private static final Option OPTION_invokeRevocationWithCert = new Option(
            "r",
            "revokecert",
            true,
            "invoke a revocation transaction; <arg> is the file path and name of certificate to revoke in PEM format.");

    private static final Option OPTION_invokeRevocation =
            new Option("R", "revoke", false, "invoke a revocation transaction " + "with data from configuration.");

    private static final Option OPTION_invokeEnrollment = new Option(
            "e",
            "enroll",
            true,
            "invoke a certificate enrollment " + "transaction; <arg> is the file path "
                    + "and name where the newly enrolled " + "certificate and the "
                    + "corresponding private key will be " + "written in PEM format.");
    private static final String Invoke_appendix = PREFIX_APPENDIX + OPTION_invokeEnrollment.getOpt() + " option.";

    private static final Option OPTION_enrollmentKeystore = new Option(
            "k",
            "enrollmentKeystore",
            true,
            "<arg> is the file path and name to " + "write the enrolled certificate, " + "chain, and private key "
                    + "in PKCS#12 format" + Invoke_appendix);

    private static final Option OPTION_enrollmentKeystorePassword = new Option(
            "w",
            "enrollmentKeystorePassword",
            true,
            "<arg> is the password to be used " + "for encrypting the " + "enrollmentKeystore. This "
                    + "option can be used in conjunction " + "with the -" + OPTION_enrollmentKeystore.getOpt()
                    + " option.");

    private static final Option OPTION_enrollmentChain = new Option(
            "n",
            "enrollmentChain",
            true,
            "<arg> is the file path and name to " + "write the newly enrolled certificate "
                    + "and its chain (excluding the root " + "certifiate) in PEM format" + Invoke_appendix);

    private static final Option OPTION_getRootCaCertificateUpdate = new Option(
            "u",
            "getRootCaCertificateUpdate",
            false,
            "invoke a Get root CA " + "certificate update GENM " + "request; optional <arg> is the "
                    + "file path and name of certificate " + "to get an update for in PEM format.");

    private static final String RootCaCertificateUpdate_appendix =
            PREFIX_APPENDIX + OPTION_getRootCaCertificateUpdate.getOpt() + " option.";

    private static final Option OPTION_NewWithNew = new Option(
            "W",
            "NewWithNew",
            true,
            "<arg> is the file path and name of " + "the new root CA certificate to " + "write in PEM format"
                    + RootCaCertificateUpdate_appendix);
    private static final Option OPTION_NewWithOld = new Option(
            "N",
            "NewWithOld",
            true,
            "<arg> is the path and name of the " + "file to write any received " + "new root CA public key signed "
                    + "with the old private root CA key" + RootCaCertificateUpdate_appendix);
    private static final Option OPTION_OldWithNew = new Option(
            "O",
            "OldWithNew",
            true,
            "<arg> is the path and name of the " + "file to write any received " + "certificate containing the "
                    + "old root CA public key signed " + "with the new private root CA key"
                    + RootCaCertificateUpdate_appendix);

    private static final Option OPTION_getCrls = new Option(
            "l",
            "getCrls",
            true,
            "invoke a CRL Update Retrieval " + "GENM request; <arg> is the file " + "path and name of CRLs to write "
                    + "in PEM format.");

    private static final String Crls_appendix = PREFIX_APPENDIX + OPTION_getCrls.getOpt() + " option.";

    private static final Option OPTION_serial = new Option(
            "S",
            "serial",
            true,
            "<arg> is the serial number of the " + "certificate to revoke with the " + "-R option.");

    private static final Option OPTION_issuer = new Option(
            "I",
            "issuer",
            true,
            "<arg> can be the issuer of the " + "certificate to revoke with the " + "-R option; "
                    + "<arg> can also be the issuer in " + "CRLSource to consult in "
                    + "conjunction with the -l option.");

    private static final Option OPTION_dpn =
            new Option("D", "dpn", true, "<arg> is the DistributionPointName in CRLSource to consult" + Crls_appendix);

    private static final Option OPTION_thisUpdate = new Option(
            "U",
            "thisUpdate",
            true,
            "<arg> is the thisUpdate time in " + "CRLStatus of the most recent CRL " + "knowns by the client; "
                    + "format is \"" + DATE_FORMAT + "\" or \"now\"" + Crls_appendix);

    private static final Option OPTION_oldCRL = new Option(
            "L",
            "oldCRL",
            true,
            "<arg> is the CRL for which an update " + "is requested; this is an alternative "
                    + "to using the --issuer, --dpn, and " + "--thisUpdate options" + Crls_appendix);

    private static final Option OPTION_getCertificateRequestTemplate = new Option(
            "t",
            "getCertificateRequestTemplate",
            true,
            "invoke a Get certificate request template GENM request, <arg> is the file path and name of the request template to write in DER format");
    private static final Option OPTION_getCaCertificates = new Option(
            "a",
            "getCaCertificates",
            true,
            "invoke a Get CA certificates " + "GENM request, <arg> is the file " + "path and name of certificates "
                    + "to write in PEM format.");

    private static final Options cliOptions = new Options();

    static {
        final OptionGroup transactionOption = new OptionGroup();
        transactionOption.addOption(OPTION_help);
        transactionOption.addOption(OPTION_invokeEnrollment);
        transactionOption.addOption(OPTION_invokeRevocation);
        transactionOption.addOption(OPTION_invokeRevocationWithCert);
        transactionOption.addOption(OPTION_getCaCertificates);
        transactionOption.addOption(OPTION_getCertificateRequestTemplate);
        OPTION_getRootCaCertificateUpdate.setOptionalArg(true);
        transactionOption.addOption(OPTION_getRootCaCertificateUpdate);
        transactionOption.addOption(OPTION_getCrls);
        transactionOption.setRequired(true);

        cliOptions.addOptionGroup(transactionOption);

        OPTION_configfile.setRequired(true);
        cliOptions.addOption(OPTION_configfile);
        cliOptions.addOption(OPTION_certProfile);
        cliOptions.addOption(OPTION_configroot);

        cliOptions.addOption(OPTION_enrollmentChain);
        cliOptions.addOption(OPTION_enrollmentKeystore);
        cliOptions.addOption(OPTION_enrollmentKeystorePassword);

        cliOptions.addOption(OPTION_NewWithNew);
        cliOptions.addOption(OPTION_NewWithOld);
        cliOptions.addOption(OPTION_OldWithNew);

        cliOptions.addOption(OPTION_serial);
        OPTION_issuer.setArgs(Option.UNLIMITED_VALUES);
        cliOptions.addOption(OPTION_issuer);
        cliOptions.addOption(OPTION_dpn);
        cliOptions.addOption(OPTION_thisUpdate);
        cliOptions.addOption(OPTION_oldCRL);
    }

    private static int doEnrollment(final CommandLine cmd, final CmpClient client)
            throws IOException, GeneralSecurityException {
        final CmpClient.EnrollmentResult ret = client.invokeEnrollment();
        if (ret == null) {
            return 1;
        }

        try (OutputStream out = new FileOutputStream(cmd.getOptionValue(OPTION_invokeEnrollment))) {
            final X509Certificate enrolledCertificate = ret.getEnrolledCertificate();
            if (enrolledCertificate != null) {
                CredentialWriter.writeCert(enrolledCertificate, out);
            }
            final PrivateKey privateKey = ret.getPrivateKey();
            if (privateKey != null) {
                CredentialWriter.writePrivateKey(privateKey, out);
            }
        }
        final List<X509Certificate> enrollmentChain = ret.getEnrollmentChain();
        if (cmd.hasOption(OPTION_enrollmentChain) && enrollmentChain != null && !enrollmentChain.isEmpty()) {
            try (OutputStream out = new FileOutputStream(cmd.getOptionValue(OPTION_enrollmentChain))) {
                for (final X509Certificate cert : enrollmentChain) {
                    CredentialWriter.writeCert(cert, out);
                }
            }
        }
        final PrivateKey enrolledPrivateKey = ret.getPrivateKey();
        if (cmd.hasOption(OPTION_enrollmentKeystore)) {
            if (!cmd.hasOption(OPTION_enrollmentKeystorePassword)) {
                System.err.println("--" + OPTION_enrollmentKeystore.getLongOpt() + " without --"
                        + OPTION_enrollmentKeystorePassword.getLongOpt() + " given, won't write keystore");
            } else if (enrolledPrivateKey == null) {
                System.err.println("no private key accessible, won't write keystore");
            } else {
                try (OutputStream out = new FileOutputStream(cmd.getOptionValue(OPTION_enrollmentKeystore))) {
                    final List<X509Certificate> chainAndCert = ret.getEnrollmentChain();
                    CredentialWriter.writeKeystore(
                            chainAndCert.toArray(new X509Certificate[chainAndCert.size()]),
                            enrolledPrivateKey,
                            cmd.getOptionValue(OPTION_enrollmentKeystorePassword)
                                    .toCharArray(),
                            out);
                }
            }
        }
        return 0;
    }

    private static int doGetCaCertificates(final CommandLine cmd, final CmpClient client) throws IOException {
        final List<X509Certificate> certs = client.getCaCertificates();
        if (certs == null) {
            return 1;
        }
        if (!certs.isEmpty()) {
            try (OutputStream out = new FileOutputStream(cmd.getOptionValue(OPTION_getCaCertificates))) {
                for (final X509Certificate cert : certs) {
                    CredentialWriter.writeCert(cert, out);
                }
            } catch (final CertificateEncodingException e) {
                e.printStackTrace();
            }
        }
        return 0;
    }

    private static int doGetCertificateRequestTemplate(final CommandLine cmd, final CmpClient client)
            throws IOException {
        final byte[] template = client.getCertificateRequestTemplate();
        if (template == null) {
            return 1;
        }

        try (OutputStream out = new FileOutputStream(cmd.getOptionValue(OPTION_getCertificateRequestTemplate))) {
            out.write(template);
        }
        return 0;
    }

    private static int doGetCrls(final CommandLine cmd, final CmpClient client)
            throws java.text.ParseException, IOException, GeneralSecurityException {
        List<X509CRL> crls = null;
        if (cmd.hasOption(OPTION_oldCRL)) {
            final X509CRL crl = CredentialLoader.loadCRLs(new File(cmd.getOptionValue(OPTION_oldCRL)).toURI())
                    .get(0);
            crls = client.getCrls(
                    cmd.getOptionValues(OPTION_dpn),
                    null,
                    new String[] {crl.getIssuerX500Principal().getName()},
                    crl.getThisUpdate());
        } else {
            Date thisUpdateDate = null;
            if (cmd.hasOption(OPTION_thisUpdate)) {
                final String thisUpdateString = cmd.getOptionValue(OPTION_thisUpdate);
                if ("now".equalsIgnoreCase(thisUpdateString)) {
                    thisUpdateDate = new Date();
                } else {
                    thisUpdateDate = DATE_PARSER.parse(thisUpdateString);
                }
            }
            crls = client.getCrls(
                    cmd.getOptionValues(OPTION_dpn), null, cmd.getOptionValues(OPTION_issuer), thisUpdateDate);
        }
        if (crls == null) {
            return 1;
        }
        if (!crls.isEmpty()) {
            try (OutputStream out = new FileOutputStream(cmd.getOptionValue(OPTION_getCrls))) {
                for (final X509CRL crl : crls) {
                    CredentialWriter.writeCrl(crl, out);
                }
            }
        }
        return 0;
    }

    private static int doGetRootCaCertificateUpdate(final CommandLine cmd, final CmpClient client)
            throws java.text.ParseException, CRLException, IOException {
        X509Certificate oldRootCaCertificate = null;
        if (cmd.getOptionValue(OPTION_getRootCaCertificateUpdate) != null) {
            oldRootCaCertificate = CredentialLoader.loadCertificates(
                            new File(cmd.getOptionValue(OPTION_getRootCaCertificateUpdate)).toURI())
                    .get(0);
        }
        final RootCaCertificateUpdateResponse ret = client.getRootCaCertificateUpdate(oldRootCaCertificate);
        if (ret == null) {
            return 1;
        }
        writeCert(cmd, ret.getNewWithNew(), OPTION_NewWithNew);
        writeCert(cmd, ret.getNewWithOld(), OPTION_NewWithOld);
        writeCert(cmd, ret.getOldWithNew(), OPTION_OldWithNew);
        return 0;
    }

    public static void main(final String[] args) {
        final int ret = runClient(args);
        System.exit(ret);
    }

    private static void printHelp() {
        final HelpFormatter formatter = new HelpFormatter();
        formatter.setOptionComparator(null);
        formatter.printHelp("java -jar path/to/CmpClient.jar", cliOptions);
    }

    public static int runClient(final String... args) {
        final CommandLineParser parser = new DefaultParser(true);
        try {
            final CommandLine cmd = parser.parse(cliOptions, args);
            if (cmd.hasOption(OPTION_help)) {
                printHelp();
                return 0;
            }
            if (cmd.hasOption(OPTION_configroot)) {
                ConfigFileLoader.setConfigFileBase(new File(cmd.getOptionValue(OPTION_configroot)));
            }
            int initialRequestType = -1;
            final ClientConfiguration config;
            try {
                config = YamlConfigLoader.loadConfig(cmd.getOptionValue(OPTION_configfile), ClientConfiguration.class);
            } catch (final Exception ex) {
                System.err.println("Client failed. Reason: configfile parsing failed:" + ex);
                return 1;
            }
            ClientContextImpl clientContext = null;
            final String cliCertProfile = cmd.getOptionValue(OPTION_certProfile);
            if (cmd.hasOption(OPTION_getCaCertificates)
                    || cmd.hasOption(OPTION_getCertificateRequestTemplate)
                    || cmd.hasOption(OPTION_getCrls)
                    || cmd.hasOption(OPTION_getRootCaCertificateUpdate)) {
                initialRequestType = PKIBody.TYPE_GEN_MSG;
            } else if (cmd.hasOption(OPTION_invokeRevocation) || cmd.hasOption(OPTION_invokeRevocationWithCert)) {
                initialRequestType = PKIBody.TYPE_REVOCATION_REQ;
            } else if (cmd.hasOption(OPTION_invokeEnrollment)) {
                clientContext = config.getClientContext(cliCertProfile);
                initialRequestType = clientContext.getEnrollmentContext().getEnrollmentType();
            }

            final UpstreamInterface upstreamInterface =
                    UpstreamInterfaceFactory.create(config.getMessageInterface(cliCertProfile, initialRequestType));

            final UpstreamExchange upstreamExchange =
                    (request, certProfile, bodyTypeOfFirstRequest) -> upstreamInterface.apply(request, certProfile);

            if (cmd.hasOption(OPTION_invokeRevocationWithCert)) {
                final X509Certificate certToRevoke = CredentialLoader.loadCertificates(
                                new File(cmd.getOptionValue(OPTION_invokeRevocationWithCert))
                                        .getAbsoluteFile()
                                        .toURI())
                        .get(0);
                final RevocationContextImpl revocationContext = new RevocationContextImpl();
                revocationContext.setIssuer(
                        certToRevoke.getIssuerX500Principal().getName());
                revocationContext.setSerialNumber(certToRevoke.getSerialNumber());
                clientContext = config.getClientContext(cliCertProfile);
                clientContext.setRevocationContext(revocationContext);
            } else if (cmd.hasOption(OPTION_invokeRevocation)) {
                final RevocationContextImpl revocationContext = new RevocationContextImpl();
                revocationContext.setIssuer(cmd.getOptionValue(OPTION_issuer));
                String serialAsString =
                        cmd.getOptionValue(OPTION_serial).toLowerCase().trim();
                if (serialAsString != null) {
                    int base = 10;
                    if (serialAsString.matches(".*[abcdef].*")) {
                        base = 16;
                    } else if (serialAsString.startsWith("0x")) {
                        base = 16;
                        serialAsString = serialAsString.substring(2);
                    } else if (serialAsString.startsWith("0")) {
                        base = 8;
                        serialAsString = serialAsString.substring(1);
                    } else if (serialAsString.endsWith("h") || serialAsString.matches(".*[abcdef].*")) {
                        base = 16;
                    }
                    serialAsString = serialAsString.replaceAll("[^1234567890abcdef]", "");
                    revocationContext.setSerialNumber(new BigInteger(serialAsString, base));
                }
                clientContext = config.getClientContext(cliCertProfile);
                clientContext.setRevocationContext(revocationContext);
            }

            final CmpClient client = new CmpClient(
                    cliCertProfile,
                    upstreamExchange,
                    config.getMessageConfiguration(cliCertProfile, initialRequestType),
                    clientContext);

            if (cmd.hasOption(OPTION_invokeEnrollment)) {
                return doEnrollment(cmd, client);
            }
            if (cmd.hasOption(OPTION_invokeRevocation) || cmd.hasOption(OPTION_invokeRevocationWithCert)) {
                return client.invokeRevocation() ? 0 : 1;
            }
            if (cmd.hasOption(OPTION_getCaCertificates)) {
                return doGetCaCertificates(cmd, client);
            }
            if (cmd.hasOption(OPTION_getCertificateRequestTemplate)) {
                return doGetCertificateRequestTemplate(cmd, client);
            }
            if (cmd.hasOption(OPTION_getCrls)) {
                return doGetCrls(cmd, client);
            }
            if (cmd.hasOption(OPTION_getRootCaCertificateUpdate)) {
                return doGetRootCaCertificateUpdate(cmd, client);
            }
            System.err.println("No CMP command given");
            return 2;
        } catch (final ParseException | java.text.ParseException e) {
            System.err.println("Client failed. Reason: " + e.getMessage());
            printHelp();
            return 3;
        } catch (final Throwable e) {
            System.err.println("Client failed. Reason: " + e.getCause());
            return 4;
        }
    }

    private static void writeCert(final CommandLine cmd, X509Certificate cert, Option opt) {
        if (cmd.hasOption(opt) && cert != null) {
            try (OutputStream out = new FileOutputStream(cmd.getOptionValue(opt))) {
                CredentialWriter.writeCert(cert, out);
            } catch (final CertificateEncodingException | IOException e) {
                e.printStackTrace();
            }
        }
    }
}
