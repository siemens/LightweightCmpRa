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

package com.siemens.pki.lightweightcmpra.downstream.offline;

import com.siemens.pki.lightweightcmpra.configuration.OfflineFileServerConfig;
import com.siemens.pki.lightweightcmpra.downstream.DownstreamInterface;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * a file system based downstream interface
 *
 */
public class CmpOfflineFileServer implements DownstreamInterface {

    private static final Logger LOGGER = LoggerFactory.getLogger(CmpOfflineFileServer.class);

    static final SimpleDateFormat DATE_FORMATTER = new SimpleDateFormat("yyMMddHHmmssZ");

    private final File inputDirectory;

    private final File outputDirectory;

    private final ExFunction messageHandler;

    /**
     *
     * @param config
     *            the configuration
     * @param messageHandler
     *            related downstream interface handler
     * @throws IOException
     *             in case of error
     */
    public CmpOfflineFileServer(final OfflineFileServerConfig config, final ExFunction messageHandler)
            throws IOException {
        this.messageHandler = messageHandler;
        inputDirectory = new File(config.getInputDirectory());
        if (!inputDirectory.isDirectory() || !inputDirectory.canWrite()) {
            throw new IOException(config.getInputDirectory() + " is not a writable directory");
        }
        outputDirectory = new File(config.getOutputDirectory());
        if (!outputDirectory.isDirectory() || !outputDirectory.canWrite()) {
            throw new IOException(config.getOutputDirectory() + " is not a writable directory");
        }
        final long pollInterval = config.getInputDirectoryPollcycle() * 1000L;
        final Timer pollTimer = new Timer(true);
        final TimerTask task = new TimerTask() {

            @Override
            public void run() {
                pollInputDirectory();
            }
        };

        pollTimer.schedule(task, new Date(System.currentTimeMillis() + pollInterval), pollInterval);
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
            final byte[] response;
            try (FileInputStream iStream = new FileInputStream(aktFile)) {
                response = messageHandler.apply(iStream.readAllBytes());
                if (response == null) {
                    continue;
                }
            } catch (final Exception ex) {
                LOGGER.error("error processing request from " + aktFile, ex);
                continue;
            } finally {
                aktFile.delete();
            }
            final File outFile;
            synchronized (DATE_FORMATTER) {
                outFile =
                        new File(outputDirectory, "REP_" + DATE_FORMATTER.format(new Date()) + "_" + aktFile.getName());
            }
            try (FileOutputStream outStream = new FileOutputStream(outFile)) {
                outStream.write(response);
            } catch (final IOException ex) {
                LOGGER.warn("error writing message to filesystem", ex);
            }
        }
    }
}
