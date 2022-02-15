package com.siemens.pki.lightweightcmpra.cryptoservices;

import com.siemens.pki.lightweightcmpra.config.xmlparser.TRUSTCREDENTIALS;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class TrustCredentialAdapterTest {

    private static final AlgorithmIdentifier signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
    private static final AlgorithmIdentifier digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(signatureAlgorithm);
    private static final BcX509ExtensionUtils x509ExtensionUtils = new BcX509ExtensionUtils();
    private static final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider());
    private static final String KEYSTORE_PASSWORD = "password";

    private AsymmetricCipherKeyPair trustKeyPair;
    private X509CertificateHolder trustCertificate;

    private final TRUSTCREDENTIALS trustcredentials = new TRUSTCREDENTIALS();

    public TrustCredentialAdapterTest() throws IOException, OperatorCreationException {
    }

    @Before
    public void setUp() throws Exception {
        trustKeyPair = generateKeyPair();
        trustCertificate = generateTestCertificateHolder(trustKeyPair.getPrivate(), trustKeyPair.getPublic(), new X500Name("CN=trust"), new X500Name("CN=trust"), 100);

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(null, KEYSTORE_PASSWORD.toCharArray());
        PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(((RSAKeyParameters) trustKeyPair.getPrivate()).getModulus(), ((RSAKeyParameters) trustKeyPair.getPrivate()).getExponent()));
        keystore.setKeyEntry("1", key, KEYSTORE_PASSWORD.toCharArray(), new Certificate[]{new JcaX509CertificateConverter()
                .getCertificate(trustCertificate)});

        File tempFile = File.createTempFile("keystore",".p12");
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            keystore.store(fos, KEYSTORE_PASSWORD.toCharArray());
        }

        trustcredentials.setEnablePreferCRLs(false);
        trustcredentials.setEnableCRLDistPoints(false);
        trustcredentials.setEnableOcspCheck(false);
        trustcredentials.setTrustStorePath(tempFile.getAbsolutePath());
        trustcredentials.setTrustStorePassword(KEYSTORE_PASSWORD);
    }

    @Test
    public void testValidChainWithDisabledCrlCheck() throws Exception {
        // setup
        trustcredentials.setEnableCrlCheck(false);
        TrustCredentialAdapter trustCredentialAdapter = new TrustCredentialAdapter(trustcredentials);

        AsymmetricCipherKeyPair intermediateKeyPair = generateKeyPair();
        X509CertificateHolder intermediateCert = generateTestCertificateHolder(trustKeyPair.getPrivate(), intermediateKeyPair.getPublic(), new X500Name("CN=intermediate"), trustCertificate.getSubject(), 101);

        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        X509CertificateHolder cert = generateTestCertificateHolder(intermediateKeyPair.getPrivate(), keyPair.getPublic(), new X500Name("CN=cert"), intermediateCert.getSubject(), 102);

        // act
        List<? extends X509Certificate> result = trustCredentialAdapter.validateCertAgainstTrust(certificateConverter.getCertificate(cert),
                Arrays.asList(certificateConverter.getCertificate(cert), certificateConverter.getCertificate(intermediateCert)));

        // check
        Assert.assertEquals(2, result.size());
    }

    @Test
    public void testValidChainWithEnabledCrlCheck() throws Exception {
        // setup
        trustcredentials.setEnableCrlCheck(true);
        TrustCredentialAdapter trustCredentialAdapter = new TrustCredentialAdapter(trustcredentials);

        AsymmetricCipherKeyPair intermediateKeyPair = generateKeyPair();
        X509CertificateHolder intermediateCert = generateTestCertificateHolder(trustKeyPair.getPrivate(), intermediateKeyPair.getPublic(), new X500Name("CN=intermediate"), trustCertificate.getSubject(), 101);

        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        X509CertificateHolder cert = generateTestCertificateHolder(intermediateKeyPair.getPrivate(), keyPair.getPublic(), new X500Name("CN=cert"), intermediateCert.getSubject(), 102);

        // act
        // TODO: This one fails due to enabled CRL check, but why?
        List<? extends X509Certificate> result = trustCredentialAdapter.validateCertAgainstTrust(certificateConverter.getCertificate(cert),
                Arrays.asList(certificateConverter.getCertificate(cert), certificateConverter.getCertificate(intermediateCert)));

        // check
        Assert.assertEquals(2, result.size());
    }

    @Test
    public void testValidChainWithDisabledCrlCheckAndWithoutKeyUsage() throws Exception {
        // setup
        trustcredentials.setEnableCrlCheck(false);
        TrustCredentialAdapter trustCredentialAdapter = new TrustCredentialAdapter(trustcredentials);

        AsymmetricCipherKeyPair intermediateKeyPair = generateKeyPair();
        X509CertificateHolder intermediateCert = generateTestCertificateHolderWithoutKeyUsage(trustKeyPair.getPrivate(), intermediateKeyPair.getPublic(), new X500Name("CN=intermediate"), trustCertificate.getSubject(), 101);

        AsymmetricCipherKeyPair keyPair = generateKeyPair();
        X509CertificateHolder cert = generateTestCertificateHolderWithoutKeyUsage(intermediateKeyPair.getPrivate(), keyPair.getPublic(), new X500Name("CN=cert"), intermediateCert.getSubject(), 102);

        // act
        // TODO: I think this should fail due to missing keyUsage
        List<? extends X509Certificate> result = trustCredentialAdapter.validateCertAgainstTrust(certificateConverter.getCertificate(cert),
                Arrays.asList(certificateConverter.getCertificate(cert), certificateConverter.getCertificate(intermediateCert)));

        // check
        Assert.assertEquals(2, result.size());
        Assert.assertNull(cert.getExtension(Extension.keyUsage)); // just make sure that my assumption with keyUsage being null is correct
        Assert.assertNull(intermediateCert.getExtension(Extension.keyUsage)); // just make sure that my assumption with keyUsage being null is correct
    }

    private X509CertificateHolder generateTestCertificateHolder(AsymmetricKeyParameter privateKey, AsymmetricKeyParameter publicKey, X500Name subject, X500Name issuer, int serialNumber) throws OperatorCreationException, IOException {
        ContentSigner sigGen = new BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm).build(privateKey);
        Instant now = Instant.now();
        Instant later = now.plus(Duration.ofHours(100));
        BcX509v3CertificateBuilder certGen = new BcX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(serialNumber),
                Date.from(now),
                Date.from(later),
                subject,
                publicKey
        );
        certGen.addExtension(Extension.subjectKeyIdentifier, false, x509ExtensionUtils.createSubjectKeyIdentifier(publicKey));
        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(20)); // setting number of allowed intermediates
        certGen.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        return certGen.build(sigGen);

    }

    private X509CertificateHolder generateTestCertificateHolderWithoutKeyUsage(AsymmetricKeyParameter privateKey, AsymmetricKeyParameter publicKey, X500Name subject, X500Name issuer, int serialNumber) throws OperatorCreationException, IOException {
        ContentSigner sigGen = new BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm).build(privateKey);
        Instant now = Instant.now();
        Instant later = now.plus(Duration.ofHours(100));
        BcX509v3CertificateBuilder certGen = new BcX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(serialNumber),
                Date.from(now),
                Date.from(later),
                subject,
                publicKey
        );
        certGen.addExtension(Extension.subjectKeyIdentifier, false, x509ExtensionUtils.createSubjectKeyIdentifier(publicKey));
        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(20)); // setting number of allowed intermediates

        return certGen.build(sigGen);

    }

    private AsymmetricCipherKeyPair generateKeyPair() {
        AsymmetricCipherKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        keyPairGenerator.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), 4096, PrimeCertaintyCalculator.getDefaultCertainty(32)));
        return keyPairGenerator.generateKeyPair();
    }
}