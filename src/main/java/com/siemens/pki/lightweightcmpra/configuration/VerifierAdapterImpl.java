/*
 *  Copyright (c) 2025 Siemens AG
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

import java.lang.reflect.InvocationTargetException;

import javax.xml.bind.annotation.XmlElement;

import org.openapitools.client.ApiException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;
import com.siemens.pki.cmpracomponent.configuration.VerifierAdapter;

public class VerifierAdapterImpl extends CertProfileBodyTypeConfigItem implements VerifierAdapter {

	private String factoryClass;
	private String factoryMethod;
	private VerifierAdapter implementation;
	
	   public String getFactoryMethod() {
		return factoryMethod;
	}
	    @XmlElement(required = true)
	public void setFactoryMethod(String factoryMethod) {
		this.factoryMethod = factoryMethod;
	}
	@Override
	public byte[] getFreshRatNonce(byte[] transactionId) throws ApiException {
		checkCreateImplementation();
		return implementation.getFreshRatNonce(transactionId);
	}
	public String getFactoryClass() {
	        return factoryClass;
	    }

	@Override
	public String processRatVerification(byte[] transactionId, byte[] evidence)
			throws ApiException, InterruptedException {
		checkCreateImplementation();
		 return implementation.processRatVerification(transactionId, evidence);
	}
	
	   @XmlElement(required = true)
	    public void setFactoryClass(final String factoryClass) {
	        this.factoryClass = factoryClass;
	    }

	   
	   private void checkCreateImplementation() {
	        if (implementation != null) {
	            return;
	        }
	        try {
	            implementation = (VerifierAdapter)
	                    Class.forName(factoryClass).getMethod(factoryMethod).invoke(null);
	        } catch (final IllegalAccessException
	                | IllegalArgumentException
	                | InvocationTargetException
	                | NoSuchMethodException
	                | SecurityException
	                | ClassNotFoundException e) {
	            final String msg = "could not instanciate RAT verify adapter " + factoryClass;
	            LOGGER.error(msg, e);
	            throw new RuntimeException(msg, e);
	        }
	    }
	   
	   private static final Logger LOGGER = LoggerFactory.getLogger(VerifierAdapterImpl.class);
	
}
