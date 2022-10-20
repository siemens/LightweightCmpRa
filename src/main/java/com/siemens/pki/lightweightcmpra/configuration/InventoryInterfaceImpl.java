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

import java.lang.reflect.InvocationTargetException;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.cmpracomponent.configuration.CheckAndModifyResult;
import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;

@XmlAccessorType(XmlAccessType.PROPERTY)
public class InventoryInterfaceImpl extends CertProfileBodyTypeConfigItem
        implements InventoryInterface {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(InventoryInterfaceImpl.class);

    private String implementingClass;

    private InventoryInterface implementation;

    @Override
    public CheckAndModifyResult checkAndModifyCertRequest(
            final byte[] transactionID, final String requesterDn,
            final byte[] certTemplate, final String requestedSubjectDn) {
        checkCreateImplementation();
        return ifNotNull(implementation,
                x -> x.checkAndModifyCertRequest(transactionID, requesterDn,
                        certTemplate, requestedSubjectDn));
    }

    @Override
    public boolean checkP10CertRequest(final byte[] transactionID,
            final String requesterDn, final byte[] pkcs10CertRequest,
            final String requestedSubjectDn) {
        checkCreateImplementation();
        return ifNotNull(implementation,
                x -> x.checkP10CertRequest(transactionID, requesterDn,
                        pkcs10CertRequest, requestedSubjectDn));
    }

    public String getImplementingClass() {
        return implementingClass;
    }

    @Override
    public boolean learnEnrollmentResult(final byte[] transactionID,
            final byte[] certificate, final String serialNumber,
            final String subjectDN, final String issuerDN) {
        checkCreateImplementation();
        return ifNotNull(implementation,
                x -> x.learnEnrollmentResult(transactionID, certificate,
                        serialNumber, subjectDN, issuerDN));
    }

    @XmlElement(required = true)
    public void setImplementingClass(final String implementingClass) {
        this.implementingClass = implementingClass;
    }

    private void checkCreateImplementation() {
        if (implementation != null) {
            return;
        }
        try {
            implementation = (InventoryInterface) Class
                    .forName(implementingClass).getConstructor().newInstance();
        } catch (final InstantiationException | IllegalAccessException
                | IllegalArgumentException | InvocationTargetException
                | NoSuchMethodException | SecurityException
                | ClassNotFoundException e) {
            final String msg =
                    "could not instanciate Inventory " + implementingClass;
            LOGGER.error(msg, e);
            throw new RuntimeException(msg, e);
        }
    }

}
