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

import javax.xml.bind.annotation.XmlElement;

/**
 * offline upstream directory interface configuration
 *
 *
 */
public class OfflineFileClientConfig extends AbstractUpstreamInterfaceConfig {

    private String inputDirectory;

    private long inputDirectoryPollcycle = 10;

    private String outputDirectory;

    public String getInputDirectory() {
        return inputDirectory;
    }

    public long getInputDirectoryPollcycle() {
        return inputDirectoryPollcycle;
    }

    public String getOutputDirectory() {
        return outputDirectory;
    }

    @XmlElement(required = true)
    public void setInputDirectory(final String inputDirectory) {
        this.inputDirectory = inputDirectory;
    }

    public void setInputDirectoryPollcycle(final long inputDirectoryPollcycle) {
        this.inputDirectoryPollcycle = inputDirectoryPollcycle;
    }

    @XmlElement(required = true)
    public void setOutputDirectory(final String outputDirectory) {
        this.outputDirectory = outputDirectory;
    }
}
