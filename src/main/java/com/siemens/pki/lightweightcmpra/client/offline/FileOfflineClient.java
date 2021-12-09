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
package com.siemens.pki.lightweightcmpra.client.offline;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

import javax.xml.bind.JAXB;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;

import com.siemens.pki.lightweightcmpra.config.xmlparser.OFFLINEFILECLIENTCONFIGURATION;
import com.siemens.pki.lightweightcmpra.msgprocessing.MsgOutputProtector;
import com.siemens.pki.lightweightcmpra.msgprocessing.UpstreamNestingFunctionIF;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;

/**
 * a file system based upstream client
 *
 */
public class FileOfflineClient extends OfflineClient {

    private final File inputDirectory;
    private final File outputDirectory;

    /**
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @param localResponseProtector
     *            protector used to protect locally generated errors and
     *            responses
     * @param nestingFunction
     *            function used for adding protection (nesting)
     * @throws IOException
     *             in case of error
     */
    public FileOfflineClient(final OFFLINEFILECLIENTCONFIGURATION config,
            final MsgOutputProtector localResponseProtector,
            final UpstreamNestingFunctionIF nestingFunction)
            throws IOException {
        super("upstream offline filesystem", localResponseProtector,
                config.getCheckAfterTime().intValue(), nestingFunction);
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
        final long pollInterval = config.getInputDirectoryPollcycle() * 1000L;
        final Timer pollTimer = new Timer(true);
        final TimerTask task = new TimerTask() {

            @Override
            public void run() {
                pollInputDirectory();
            }
        };
        pollTimer.schedule(task,
                new Date(System.currentTimeMillis() + pollInterval),
                pollInterval);
    }

    @Override
    protected void forwardRequestToInterface(final PKIMessage request)
            throws IOException {
        final File outFile = new File(outputDirectory,
                MessageDumper.msgTypeAsString(request) + request.getHeader()
                        .getTransactionID().toString().replace("#", "_")
                        + ".der");
        try (FileOutputStream outStream = new FileOutputStream(outFile)) {
            final ASN1OutputStream aout =
                    ASN1OutputStream.create(outStream, ASN1Encoding.DER);
            aout.writeObject(request);
            aout.close();
        }
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
            try (FileInputStream iStream = new FileInputStream(aktFile);
                    ASN1InputStream asn1InputStream =
                            new ASN1InputStream(iStream);) {
                responseFromInterfaceReceived(
                        PKIMessage.getInstance(asn1InputStream.readObject()));
            } catch (final IOException ex) {
                continue;
            } finally {
                aktFile.delete();
            }
        }
    }

}
