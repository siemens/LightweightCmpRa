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

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import com.siemens.pki.cmpracomponent.configuration.CkgContext;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;
import com.siemens.pki.cmpracomponent.configuration.PersistencyInterface;
import com.siemens.pki.cmpracomponent.configuration.SupportMessageHandlerInterface;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.persistency.DefaultPersistencyImplementation;
import java.util.ArrayList;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
// {@link java.util.List} sub classing works only with {@link XmlAccessType}.FIELD
@XmlAccessorType(XmlAccessType.FIELD)
public class ConfigurationImpl implements Configuration {

    static class CertProfileInfoTypeScopedList<T extends CertProfileInfoTypeConfigItem> extends ArrayList<T> {

        private static final long serialVersionUID = 1L;

        T getMatchingConfig(final String certProfile, final String infoTypeOid) {
            for (final T aktItem : this) {
                if (aktItem.matchesScope(certProfile, infoTypeOid)) {
                    return aktItem;
                }
            }
            return null;
        }
    }

    private final PersistencyInterface persistency = new DefaultPersistencyImplementation(600);

    @XmlElements({
        @XmlElement(name = "OfflineFileClient", type = OfflineFileClientConfig.class, required = false),
        @XmlElement(name = "HttpClient", type = HttpClientConfig.class, required = false),
        @XmlElement(name = "HttpsClient", type = HttpsClientConfig.class, required = false),
        @XmlElement(name = "CoapClient", type = CoapClientConfig.class, required = false),
    })
    private final CertProfileBodyTypeScopedList<AbstractUpstreamInterfaceConfig> UpstreamInterface =
            new CertProfileBodyTypeScopedList<>();

    @XmlElements({
        @XmlElement(name = "OfflineFileServer", type = OfflineFileServerConfig.class, required = false),
        @XmlElement(name = "CoapServer", type = CoapServerConfig.class, required = false),
        @XmlElement(name = "HttpServer", type = HttpServerConfig.class, required = false),
        @XmlElement(name = "HttpsServer", type = HttpsServerConfig.class, required = false)
    })
    private AbstractDownstreamInterfaceConfig DownstreamInterface;

    @XmlElement(required = false)
    private final CertProfileBodyTypeScopedList<CkgContextImpl> CkgConfiguration =
            new CertProfileBodyTypeScopedList<>();

    @XmlElement(required = true)
    private final CertProfileBodyTypeScopedList<CmpMessageInterfaceImpl> DownstreamConfiguration =
            new CertProfileBodyTypeScopedList<>();

    private final CertProfileBodyTypeScopedList<CmpMessageInterfaceImpl> UpstreamConfiguration =
            new CertProfileBodyTypeScopedList<>();

    private final CertProfileBodyTypeScopedList<EnrollmentTrustImpl> EnrollmentTrust =
            new CertProfileBodyTypeScopedList<>();

    private final CertProfileBodyTypeScopedList<BooleanConfigImpl> ForceRaVerifyOnUpstream =
            new CertProfileBodyTypeScopedList<>();

    private final CertProfileBodyTypeScopedList<BooleanConfigImpl> RaVerifiedAcceptable =
            new CertProfileBodyTypeScopedList<>();

    private final CertProfileBodyTypeScopedList<InventoryInterfaceImpl> InventoryInterface =
            new CertProfileBodyTypeScopedList<>();

    private final CertProfileBodyTypeScopedList<IntegerConfigImpl> RetryAfterTimeInSeconds =
            new CertProfileBodyTypeScopedList<>();

    private final CertProfileBodyTypeScopedList<IntegerConfigImpl> DownstreamTimeout =
            new CertProfileBodyTypeScopedList<>();

    @XmlElements({
        @XmlElement(name = "CrlUpdateRetrieval", type = CrlUpdateRetrievalHandlerImpl.class, required = false),
        @XmlElement(name = "GetCaCertificates", type = GetCaCertificatesHandlerImpl.class, required = false),
        @XmlElement(
                name = "GetCertificateRequestTemplate",
                type = GetCertificateRequestTemplateHandlerImpl.class,
                required = false),
        @XmlElement(
                name = "GetRootCaCertificateUpdate",
                type = GetRootCaCertificateUpdateHandlerImpl.class,
                required = false)
    })
    private final CertProfileInfoTypeScopedList<SupportMessageHandlerInterfaceImpl> SupportMessageHandlerInterface =
            new CertProfileInfoTypeScopedList<>();

    @Override
    public CkgContext getCkgConfiguration(final String certProfile, final int bodyType) {
        return CkgConfiguration.getMatchingConfig(certProfile, bodyType);
    }

    @Override
    public CmpMessageInterface getDownstreamConfiguration(final String certProfile, final int bodyType) {
        return DownstreamConfiguration.getMatchingConfig(certProfile, bodyType, "DownstreamConfiguration");
    }

    @Override
    public int getDownstreamTimeout(final String certProfile, final int bodyType) {
        final IntegerConfigImpl matchingConfig = DownstreamTimeout.getMatchingConfig(certProfile, bodyType);
        if (matchingConfig == null) {
            return 0;
        }
        final int asInt = matchingConfig.getAsInt();
        return asInt;
    }

    public AbstractDownstreamInterfaceConfig getDownstreamInterface() {
        return DownstreamInterface;
    }

    @Override
    public VerificationContext getEnrollmentTrust(final String certProfile, final int bodyType) {
        return ifNotNull(
                EnrollmentTrust.getMatchingConfig(certProfile, bodyType, "EnrollmentTrust"),
                EnrollmentTrustImpl::getVerificationContext);
    }

    @Override
    public boolean getForceRaVerifyOnUpstream(final String certProfile, final int bodyType) {
        return ForceRaVerifyOnUpstream.getMatchingConfig(certProfile, bodyType, "ForceRaVerifyOnUpstream")
                .getAsBoolean();
    }

    @Override
    public InventoryInterface getInventory(final String certProfile, final int bodyType) {
        return InventoryInterface.getMatchingConfig(certProfile, bodyType);
    }

    @Override
    public PersistencyInterface getPersistency() {
        return persistency;
    }

    @Override
    public int getRetryAfterTimeInSeconds(final String certProfile, final int bodyType) {
        return RetryAfterTimeInSeconds.getMatchingConfig(certProfile, bodyType, "RetryAfterTimeInSeconds")
                .getAsInt();
    }

    @Override
    public SupportMessageHandlerInterface getSupportMessageHandler(final String certProfile, final String infoTypeOid) {
        return SupportMessageHandlerInterface.getMatchingConfig(certProfile, infoTypeOid);
    }

    @Override
    public CmpMessageInterface getUpstreamConfiguration(final String certProfile, final int bodyType) {
        return UpstreamConfiguration.getMatchingConfig(certProfile, bodyType, "UpstreamConfiguration");
    }

    public AbstractUpstreamInterfaceConfig getUpstreamInterface(final String certProfile, final int bodyType) {
        return UpstreamInterface.getMatchingConfig(certProfile, bodyType, "UpstreamInterface");
    }

    @Override
    public boolean isRaVerifiedAcceptable(final String certProfile, final int bodyType) {
        return RaVerifiedAcceptable.getMatchingConfig(certProfile, bodyType, "RaVerifiedAcceptable")
                .getAsBoolean();
    }
}
