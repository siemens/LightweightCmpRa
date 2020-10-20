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

package com.siemens.pki.lightweightcmpra.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;
import java.util.function.Function;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.config.xmlparser.OFFLINEFILESERVERCONFIGURATION;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

/**
 * a file system based downstream interface
 *
 */
public class OfflineFileServer {

    private static final long POLL_INTERVAL_MS = 10000;
    private static final Logger LOGGER =
            LoggerFactory.getLogger(OfflineFileServer.class);
    private final File inputDirectory;
    private final File outputDirectory;

    private final Function<PKIMessage, PKIMessage> messageHandler;

    /**
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @param messageHandler
     *            related downstream interface handler
     * @throws IOException
     *             in case of error
     */
    public OfflineFileServer(final OFFLINEFILESERVERCONFIGURATION config,
            final Function<PKIMessage, PKIMessage> messageHandler)
            throws IOException {
        this.messageHandler = messageHandler;
        inputDirectory = new File(config.getInputDirectory());
        if (!inputDirectory.isDirectory() || !inputDirectory.canWrite()) {
            throw new IOException(config.getInputDirectory()
                    + " is not a writable directory");
        }
        outputDirectory = new File(config.getOutputDirectory());
        if (!outputDirectory.isDirectory() || !outputDirectory.canWrite()) {
            throw new IOException(config.getOutputDirectory()
                    + " is not a writable directory");
        }
        final Timer pollTimer = new Timer(true);
        final TimerTask task = new TimerTask() {

            @Override
            public void run() {
                pollInputDirectory();
            }
        };
        pollTimer.schedule(task,
                new Date(System.currentTimeMillis() + POLL_INTERVAL_MS),
                POLL_INTERVAL_MS);
    }

    /**
     * one poll cycle
     */
    private void pollInputDirectory() {
        final File[] listedFiles = inputDirectory.listFiles();
        if (listedFiles == null) {
            return;
        }
        for (final File aktFile : listedFiles) {
            if (!aktFile.isFile() || !aktFile.canRead()) {
                continue;
            }
            final PKIMessage response;
            try (FileInputStream iStream = new FileInputStream(aktFile);
                    ASN1InputStream asn1InputStream =
                            new ASN1InputStream(iStream);) {
                response = messageHandler.apply(
                        PKIMessage.getInstance(asn1InputStream.readObject()));
            } catch (final IOException ex) {
                continue;
            } finally {
                aktFile.delete();
            }
            if (response == null) {
                continue;
            }
            final File outFile =
                    new File(outputDirectory,
                            MessageDumper.msgTypeAsString(response)
                                    + response.getHeader().getTransactionID()
                                            .toString().replace("#", "_")
                                    + ".der");
            try (FileOutputStream outStream = new FileOutputStream(outFile)) {
                final ASN1OutputStream aout =
                        ASN1OutputStream.create(outStream, ASN1Encoding.DER);
                aout.writeObject(response);
                aout.close();
            } catch (final IOException ex) {
                LOGGER.warn("error writing message to filesystem", ex);
            }
        }
    }
}
