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
package com.siemens.pki.lightweightcmpra.test.framework;

import java.security.Key;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

/**
 *
 * utility class for signing and protection
 *
 */
public class SignHelperUtil {
    private static final DefaultSignatureAlgorithmIdentifierFinder DEFAULT_SIGNATURE_ALGORITHM_IDENTIFIER_FINDER =
            new DefaultSignatureAlgorithmIdentifierFinder();

    /**
     * Get Algorithm OID for the given algorithm. Function supports only RSA, EC
     * and EdDSA
     * and will return OID sha256WithRSAEncryption (1.2.840.113549.1.1.11) for
     * RSA,
     * ecdsa_with_SHA256 (1.2.840.10045.4.3.2) for EC, id-Ed25519 (1.3.101.112)
     * for Ed25519 and id-Ed448 (1.3.101.1123) for Ed448
     *
     * @param algorithm
     *            algorithm ("RSA", "EC", "Ed25519", "Ed448") to get OID for
     *
     * @return OID of the algorithm
     */
    public static AlgorithmIdentifier getAlgOID(final String algorithm) {
        if ("RSA".equalsIgnoreCase(algorithm)) {
            return new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.sha256WithRSAEncryption);
        } else if (algorithm.startsWith("EC")) {
            return new AlgorithmIdentifier(
                    X9ObjectIdentifiers.ecdsa_with_SHA256);
        } else if ("Ed448".equalsIgnoreCase(algorithm)) {
            return new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448);
        } else if ("Ed25519".equalsIgnoreCase(algorithm)) {
            return new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
        }
        return null;
    }

    public static AlgorithmIdentifier getSigningAlgIdFromKey(final Key key)
            throws Exception {
        return getSigningAlgIdFromKeyAlg(key.getAlgorithm());

    }

    public static AlgorithmIdentifier getSigningAlgIdFromKeyAlg(
            final String keyAlgorithm) throws Exception {
        return DEFAULT_SIGNATURE_ALGORITHM_IDENTIFIER_FINDER
                .find(getSigningAlgNameFromKeyAlg(keyAlgorithm));
    }

    /**
     * get a feasible signing algorithm for the given key
     *
     * @param key
     *            the key to fetch the algorithm from
     * @return standard java name for signature algorithm or <code>null</code>
     *         if key uses algorithms beside RSA, EC or EdDSA
     */
    public static String getSigningAlgNameFromKey(final Key key) {
        return getSigningAlgNameFromKeyAlg(key.getAlgorithm());
    }

    /**
     * get a feasible signing algorithm for the given keyAlgorithm
     *
     * @param keyAlgorithm
     *            the algorithm to calculate the name from
     * @return standard java name for signature algorithm or <code>null</code>
     *         if key uses algorithms beside RSA, EC or EdDSA
     */
    public static String getSigningAlgNameFromKeyAlg(
            final String keyAlgorithm) {
        if (keyAlgorithm.startsWith("Ed")) {
            // EdDSA key
            return keyAlgorithm;
        }
        if ("EC".equals(keyAlgorithm)) {
            // EC key
            return "SHA256withECDSA";
        }
        return "SHA256with" + keyAlgorithm;
    }

}
