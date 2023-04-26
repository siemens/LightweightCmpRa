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
package com.siemens.pki.lightweightcmpclient.configuration;

import com.siemens.pki.cmpclientcomponent.configuration.EnrollmentContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.KeyPairGeneratorFactory;
import com.siemens.pki.cmpracomponent.util.NullUtil;
import com.siemens.pki.lightweightcmpra.configuration.VerificationContextImpl;
import com.siemens.pki.lightweightcmpra.configuration.XmlPkiMessageTypeToIntAdapter;
import com.siemens.pki.lightweightcmpra.util.ConfigFileLoader;
import com.siemens.pki.lightweightcmpra.util.CredentialLoader;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class EnrollmentContextImpl implements EnrollmentContext {

    private VerificationContextImpl enrollmentTrust;
    private boolean requestImplictConfirm = true;
    private String subject;
    private boolean requestCentralKeyGeneration = false;

    private List<TemplateExtension> extensions;

    private String keyType;
    private URI oldCert;

    private int enrollmentType = EnrollmentContext.super.getEnrollmentType();

    private URI certificationRequest;

    private KeyPair createKeyPair(final String upperKeyType) throws NoSuchAlgorithmException, GeneralSecurityException {
        if (upperKeyType.startsWith("RSA")) {
            return KeyPairGeneratorFactory.getRsaKeyPairGenerator(Integer.parseInt(upperKeyType.substring(3)))
                    .genKeyPair();
        }
        if (upperKeyType.startsWith("ED")) {
            return KeyPairGeneratorFactory.getEdDsaKeyPairGenerator(keyType).generateKeyPair();
        }
        return KeyPairGeneratorFactory.getEcKeyPairGenerator(keyType).generateKeyPair();
    }

    @Override
    public KeyPair getCertificateKeypair() {
        if ((keyType == null && requestCentralKeyGeneration) || (enrollmentType == PKIBody.TYPE_P10_CERT_REQ)) {
            return null;
        }
        try {
            final KeyPair createdKeypair = createKeyPair(keyType.toUpperCase());
            if (requestCentralKeyGeneration) {
                // fake empty public key
                final SubjectPublicKeyInfo subjectPublicKey = SubjectPublicKeyInfo.getInstance(
                        createdKeypair.getPublic().getEncoded());
                final PublicKey pubKey = new PublicKey() {

                    private static final long serialVersionUID = 1L;

                    @Override
                    public String getAlgorithm() {
                        return createdKeypair.getPublic().getAlgorithm();
                    }

                    @Override
                    public byte[] getEncoded() {
                        try {
                            return new SubjectPublicKeyInfo(subjectPublicKey.getAlgorithm(), new byte[0]).getEncoded();
                        } catch (final IOException e) {
                            return null;
                        }
                    }

                    @Override
                    public String getFormat() {
                        return "X.509";
                    }
                };
                return new KeyPair(pubKey, null);
            }
            return createdKeypair;
        } catch (final NumberFormatException | GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] getCertificationRequest() {
        try {
            return NullUtil.ifNotNull(certificationRequest, cr -> ConfigFileLoader.getConfigUriAsStream(cr)
                    .readAllBytes());
        } catch (final IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public VerificationContext getEnrollmentTrust() {
        return enrollmentTrust;
    }

    @Override
    public int getEnrollmentType() {
        return enrollmentType;
    }

    @Override
    public List<TemplateExtension> getExtensions() {
        return extensions;
    }

    @Override
    public X509Certificate getOldCert() {
        return NullUtil.ifNotNull(
                oldCert, url -> CredentialLoader.loadCertificates(url).get(0));
    }

    @Override
    public boolean getRequestImplictConfirm() {
        return requestImplictConfirm;
    }

    @Override
    public String getSubject() {
        return subject;
    }

    public void setCertificationRequest(URI certificationRequest) {
        this.certificationRequest = certificationRequest;
    }

    @XmlJavaTypeAdapter(XmlPkiMessageTypeToIntAdapter.class)
    public void setEnrollmentType(Integer enrollmentType) {
        this.enrollmentType = enrollmentType;
    }

    public void setExtensions(final List<TemplateExtensionImpl> enrollmentExtensions) {
        if (extensions == null) {
            extensions = new ArrayList<>();
        }
        extensions.addAll(enrollmentExtensions);
    }

    public void setKeyType(final String keyType) {
        this.keyType = keyType;
    }

    public void setOldCert(final URI oldCert) {
        this.oldCert = oldCert;
    }

    public void setRequestCentralKeyGeneration(boolean centralKeyGeneration) {
        this.requestCentralKeyGeneration = centralKeyGeneration;
    }

    public void setRequestImplictConfirm(final boolean requestImplictConfirm) {
        this.requestImplictConfirm = requestImplictConfirm;
    }

    public void setSubject(final String subject) {
        this.subject = subject;
    }
}
