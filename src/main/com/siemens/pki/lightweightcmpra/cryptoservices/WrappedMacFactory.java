/*
 *  Copyright (c) 2021 Siemens AG
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
package com.siemens.pki.lightweightcmpra.cryptoservices;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.CipherFactory;

/**
 * factory for {@link WrappedMac}
 */
public class WrappedMacFactory {
    private static final byte[] EMPTY_STRING = new byte[0];

    public static WrappedMac createWrappedMac(final AlgorithmIdentifier macid,
            final byte[] key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        final ASN1ObjectIdentifier algorithm = macid.getAlgorithm();
        if (NISTObjectIdentifiers.id_KmacWithSHAKE128.equals(algorithm)) {
            final KMAC mac = new KMAC(128, EMPTY_STRING);
            mac.init(new KeyParameter(key));
            return in -> {
                final byte[] out = new byte[128];
                mac.reset();
                mac.update(in, 0, in.length);
                mac.doFinal(out, 0);
                return out;
            };
        }
        if (NISTObjectIdentifiers.id_KmacWithSHAKE256.equals(algorithm)) {
            final KMAC mac = new KMAC(256, EMPTY_STRING);
            mac.init(new KeyParameter(key));
            return in -> {
                final byte[] out = new byte[256];
                mac.reset();
                mac.update(in, 0, in.length);
                mac.doFinal(out, 0);
                return out;
            };
        }
        if (NISTObjectIdentifiers.id_aes128_GCM.equals(algorithm)
                || NISTObjectIdentifiers.id_aes192_GCM.equals(algorithm)
                || NISTObjectIdentifiers.id_aes256_GCM.equals(algorithm)) {
            return in -> {
                final GMac mac = new GMac(
                        (GCMBlockCipher) CipherFactory.createContentCipher(true,
                                new KeyParameter(key), macid));
                final byte[] out = new byte[256];
                mac.update(in, 0, in.length);
                mac.doFinal(out, 0);
                return out;
            };
        }

        // TODO  id-aes*-GMAC missing

        // hopefully BC will know
        final String algorithmAsString = algorithm.getId();
        final Mac mac = Mac.getInstance(algorithmAsString,
                CertUtility.BOUNCY_CASTLE_PROVIDER);
        mac.init(new SecretKeySpec(key, algorithmAsString));
        return in -> {
            mac.reset();
            return mac.doFinal(in);
        };

    }

}
