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
package com.siemens.pki.lightweightcmpra.configuration;

import static com.siemens.pki.cmpracomponent.util.NullUtil.computeDefaultIfNull;

import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class SharedSecretCredentialContextImpl extends CredentialContextImpl implements SharedSecretCredentialContext {

    private String MacAlgorithm;
    private String Prf;
    private byte[] Salt;
    private byte[] SenderKID;
    private byte[] SharedSecret;
    protected int IterationCount = SharedSecretCredentialContext.super.getIterationCount();

    protected int keyLength = SharedSecretCredentialContext.super.getkeyLength();

    protected String PasswordBasedMacAlgorithm;

    @Override
    public int getIterationCount() {
        return IterationCount;
    }

    @Override
    public int getkeyLength() {
        return keyLength;
    }

    @XmlElement(required = true)
    @Override
    public String getMacAlgorithm() {
        return computeDefaultIfNull(MacAlgorithm, SharedSecretCredentialContext.super::getMacAlgorithm);
    }

    @Override
    public String getPasswordBasedMacAlgorithm() {
        return computeDefaultIfNull(
                PasswordBasedMacAlgorithm, SharedSecretCredentialContext.super::getPasswordBasedMacAlgorithm);
    }

    @Override
    public String getPrf() {
        return computeDefaultIfNull(Prf, SharedSecretCredentialContext.super::getPrf);
    }

    @Override
    public byte[] getSalt() {
        return computeDefaultIfNull(Salt, () -> CertUtility.generateRandomBytes(20));
    }

    @Override
    public byte[] getSenderKID() {
        return computeDefaultIfNull(SenderKID, SharedSecretCredentialContext.super::getSenderKID);
    }

    @Override
    public byte[] getSharedSecret() {
        return SharedSecret;
    }

    public void setIterationCount(final int iterationCount) {
        IterationCount = iterationCount;
    }

    public void setKeyLength(final int keyLength) {
        this.keyLength = keyLength;
    }

    public void setMacAlgorithm(final String macAlgorithm) {
        MacAlgorithm = macAlgorithm;
    }

    public void setPasswordBasedMacAlgorithm(final String passwordBasedMacAlgorithm) {
        PasswordBasedMacAlgorithm = passwordBasedMacAlgorithm;
    }

    @XmlElement(required = true)
    public void setPrf(final String prf) {
        Prf = prf;
    }

    public void setSalt(final byte[] salt) {
        Salt = salt;
    }

    public void setSenderKID(final byte[] senderKID) {
        SenderKID = senderKID;
    }

    public void setSharedSecret(final byte[] sharedSecret) {
        SharedSecret = sharedSecret;
    }
}
