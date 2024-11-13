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
package com.siemens.pki.lightweightcmpra.upstream.offline;

import static com.siemens.pki.cmpracomponent.util.NullUtil.defaultIfNull;

import com.siemens.pki.lightweightcmpra.configuration.OfflineFileClientConfig;
import com.siemens.pki.lightweightcmpra.upstream.UpstreamInterface;
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
 * a file system based upstream client
 *
 */
public class CmpFileOfflineClient implements UpstreamInterface {

    static final SimpleDateFormat DATE_FORMATTER = new SimpleDateFormat("yyMMddHHmmssZ");
    private static final Logger LOGGER = LoggerFactory.getLogger(CmpFileOfflineClient.class);

    private final File inputDirectory;

    private final File outputDirectory;
    private AsyncResponseHandler asyncResponseHandler;
    private TimerTask timerTask;

    /**
     *
     * @param config
     *            configuration from configuration file
     *
     * @throws IOException
     *             in case of error
     */
    public CmpFileOfflineClient(final OfflineFileClientConfig config) throws IOException {

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
        timerTask = new TimerTask() {

            @Override
            public void run() {
                pollInputDirectory();
            }
        };
        pollTimer.schedule(timerTask, new Date(System.currentTimeMillis() + pollInterval), pollInterval);
    }

    @Override
    public byte[] apply(final byte[] request, final String certProfile) {
        final File outFile;
        synchronized (DATE_FORMATTER) {
            outFile = new File(
                    outputDirectory,
                    "REQ_" + defaultIfNull(certProfile, "") + DATE_FORMATTER.format(new Date()) + ".der");
        }
        try (FileOutputStream outStream = new FileOutputStream(outFile)) {
            outStream.write(request);
        } catch (final IOException e) {
            LOGGER.warn("error writing request to file " + outFile, e);
        }
        return null;
    }

    @Override
    public void setDelayedResponseHandler(final AsyncResponseHandler asyncResponseHandler) {
        this.asyncResponseHandler = asyncResponseHandler;
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
            try (FileInputStream iStream = new FileInputStream(aktFile)) {
                asyncResponseHandler.apply(iStream.readAllBytes());
            } catch (final Exception ex) {
                LOGGER.warn("error processing response from " + aktFile, ex);
            } finally {
                aktFile.delete();
            }
        }
    }

    @Override
    public void stop() {
        timerTask.cancel();
    }
}
