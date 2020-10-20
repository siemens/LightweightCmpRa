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
package com.siemens.pki.lightweightcmpra.util;

import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.config.xmlparser.TRUSTCREDENTIALS.MatchingPeerCertificateSubject;

/**
 * a regular expression based selector for end certificates utilized in chain
 * building
 *
 *
 */
public class RegexCertMatcher implements CertSelector {
    private static final org.slf4j.Logger LOGGER =
            LoggerFactory.getLogger(RegexCertMatcher.class);

    private final List<Pattern> pattern;

    /**
     * @param regex
     *            regular expression which has to be matched by the subject of a
     *            valid end certificate
     */
    public RegexCertMatcher(
            final Collection<MatchingPeerCertificateSubject> regex) {
        if (regex == null || regex.isEmpty()) {
            pattern = null;
            return;
        }
        pattern = regex.stream()
                .map(aktRegex -> Pattern.compile(aktRegex.getRegex()))
                .collect(Collectors.toList());
    }

    /**
     * Makes a copy of this {@code CertSelector}. Changes to the copy will not
     * affect the original and vice versa.
     *
     * @return a copy of this {@code CertSelector}
     */
    @Override
    public Object clone() {
        return this;
    }

    @Override
    public boolean match(final Certificate certificate) {
        if (pattern == null) {
            return true;
        }
        if (!(certificate instanceof X509Certificate)) {
            return false;
        }
        final String subject = ((X509Certificate) certificate)
                .getSubjectX500Principal().getName();
        for (final Pattern aktPattern : pattern) {
            if (aktPattern.matcher(subject).matches()) {
                return true;
            }
        }
        LOGGER.warn("cert " + subject + " did not match " + pattern);
        return false;
    }
}