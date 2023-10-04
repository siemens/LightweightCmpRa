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
package com.siemens.pki.lightweightcmpra.downstream.online;

import com.siemens.pki.lightweightcmpra.configuration.CoapServerConfig;
import com.siemens.pki.lightweightcmpra.downstream.DownstreamInterface;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.LinkedList;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * a COAP (RFC 7252) server needed for downstream interfaces
 *
 */
public class CmpCoapServer implements DownstreamInterface {

    static {
        CoapConfig.register();
        UdpConfig.register();
        TcpConfig.register();
    }

    private static CoapServer coapServer;
    private static final int COAP_PORT = Configuration.getStandard().get(CoapConfig.COAP_PORT);

    private static final Logger LOGGER = LoggerFactory.getLogger(CmpCoapServer.class);

    private static synchronized CoapServer getInitializedCoapServer() {
        if (coapServer != null) {
            return coapServer;
        }
        coapServer = new CoapServer();
        final Configuration config = Configuration.getStandard();
        for (final InetAddress addr : NetworkInterfacesUtil.getNetworkInterfaces()) {
            if (!addr.isLinkLocalAddress()) {
                final CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
                final InetSocketAddress bindToAddress = new InetSocketAddress(addr, COAP_PORT);
                builder.setInetSocketAddress(bindToAddress);
                builder.setConfiguration(config);
                coapServer.addEndpoint(builder.build());
            }
        }
        coapServer.start();
        return coapServer;
    }

    private final ExFunction messageHandler;

    /**
     * @param config
     *            configuration from configuration file
     * @param messageHandler
     *            related downstream interface handler
     */
    public CmpCoapServer(final CoapServerConfig config, final ExFunction messageHandler) {
        this.messageHandler = messageHandler;
        Resource previousRecource = getInitializedCoapServer().getRoot();
        final LinkedList<String> pathParts =
                new LinkedList<>(Arrays.asList(config.getServerPath().split("/")));
        if (pathParts.size() < 1) {
            LOGGER.error("empty COAP ressourcePath");
            return;
        }
        while (pathParts.size() > 1) {
            final String aktNamePart = pathParts.removeFirst();
            Resource childRessource = previousRecource.getChild(aktNamePart);
            if (childRessource == null) {
                childRessource = new CoapResource(aktNamePart);
                previousRecource.add(childRessource);
            }
            previousRecource = childRessource;
        }
        final CoapResource lastRecourceNode = new CoapResource(pathParts.getFirst()) {
            @Override
            public void handlePOST(final CoapExchange exchange) {
                handleCoapPOST(exchange);
            }
        };
        final Resource childToBeReplaced = previousRecource.getChild(pathParts.getFirst());
        if (childToBeReplaced != null) {
            for (final Resource childChild : childToBeReplaced.getChildren()) {
                lastRecourceNode.add(childChild);
            }
        }

        lastRecourceNode.getAttributes().addAttribute("cmp");
        previousRecource.add(lastRecourceNode);
    }

    private void handleCoapPOST(final CoapExchange exchange) {
        LOGGER.debug("handlePOST called");
        try {
            final byte[] responseMessage = messageHandler.apply(exchange.getRequestPayload());
            if (responseMessage != null) {
                exchange.respond(ResponseCode.CONTENT, responseMessage, MediaTypeRegistry.APPLICATION_OCTET_STREAM);
            } else {
                exchange.respond(ResponseCode.BAD_REQUEST);
            }
        } catch (final Exception e) {
            LOGGER.error("exception while processing request, sending error INTERNAL_SERVER_ERROR", e);
            exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR, "Internal error:" + e.getMessage());
        }
    }

    @Override
    public void stop() {
        coapServer.stop();
        coapServer = null;
    }
}
