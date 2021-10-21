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

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Objects;
import java.util.function.Function;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.msgvalidation.BaseCmpException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpValidationException;

/**
 * some adapter classes
 *
 */
public class MsgProcessingAdapter {

    private static final Encoder B64_ENCODER_WITHOUT_PADDING =
            Base64.getUrlEncoder().withoutPadding();

    private static final Logger LOGGER =
            LoggerFactory.getLogger(MsgProcessingAdapter.class);

    private static File msgDumpDirectory;

    static {
        final String dumpDirName = System.getProperty("dumpdir");
        if (dumpDirName != null) {
            msgDumpDirectory = new File(dumpDirName);
            if (!msgDumpDirectory.isDirectory()
                    || !msgDumpDirectory.canWrite()) {
                LOGGER.error(
                        msgDumpDirectory + " is not writable, disable dump");
                msgDumpDirectory = null;
            } else {
                LOGGER.info("dump transactions below " + msgDumpDirectory);
            }
        }
    }

    public static Function<PKIMessage, PKIMessage> adaptByteToByteFunctionToMsgHandler(
            final String interfaceName,
            final Function<byte[], byte[]> wrapped) {
        return msg -> {
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("got " + MessageDumper.dumpPkiMessage(msg));
            } else if (LOGGER.isDebugEnabled()) {
                // avoid unnecessary string processing, if debug isn't enabled
                LOGGER.debug("got " + MessageDumper.msgAsShortString(msg));
            }
            if (msg == null) {
                return null;
            }
            dumpMessage(msg, interfaceName);
            try (final ASN1InputStream asn1InputStream = new ASN1InputStream(
                    wrapped.apply(msg.getEncoded(ASN1Encoding.DER)))) {
                final PKIMessage ret =
                        PKIMessage.getInstance(asn1InputStream.readObject());
                if (LOGGER.isTraceEnabled()) {
                    LOGGER.trace("return " + MessageDumper.dumpPkiMessage(ret));
                } else if (LOGGER.isDebugEnabled()) {
                    // avoid unnecessary string processing, if debug isn't enabled
                    LOGGER.debug(
                            "return " + MessageDumper.msgAsShortString(ret));
                }
                dumpMessage(ret, interfaceName);
                checkNonce(interfaceName, msg, ret);
                return ret;
            } catch (final BaseCmpException ex) {
                throw ex;
            } catch (final Exception e) {
                throw new CmpProcessingException(interfaceName,
                        PKIFailureInfo.badDataFormat, e);
            }
        };
    }

    public static Function<PKIMessage, PKIMessage> adaptByteToInputStreamFunctionToMsgHandler(
            final String interfaceName,
            final Function<byte[], InputStream> wrapped) {
        return msg -> {
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("sending to upstream "
                        + MessageDumper.dumpPkiMessage(msg));
            } else if (LOGGER.isDebugEnabled()) {
                // avoid unnecessary string processing, if debug isn't enabled
                LOGGER.debug("sending to upstream "
                        + MessageDumper.msgAsShortString(msg));
            }
            if (msg == null) {
                return null;
            }
            dumpMessage(msg, interfaceName);
            try (final ASN1InputStream asn1InputStream = new ASN1InputStream(
                    wrapped.apply(msg.getEncoded(ASN1Encoding.DER)))) {
                final PKIMessage ret =
                        PKIMessage.getInstance(asn1InputStream.readObject());
                if (LOGGER.isTraceEnabled()) {
                    LOGGER.trace("received from upstream "
                            + MessageDumper.dumpPkiMessage(ret));
                } else if (LOGGER.isDebugEnabled()) {
                    // avoid unnecessary string processing, if debug isn't enabled
                    LOGGER.debug("received from upstream "
                            + MessageDumper.msgAsShortString(ret));
                }
                dumpMessage(ret, interfaceName);
                checkNonce(interfaceName, msg, ret);
                return ret;
            } catch (final BaseCmpException ex) {
                throw ex;
            } catch (final Exception e) {
                throw new CmpProcessingException(interfaceName,
                        PKIFailureInfo.badDataFormat, e);
            }
        };
    }

    public static Function<byte[], byte[]> adaptMsgHandlerToByteToByteFunction(
            final String interfaceName,
            final Function<PKIMessage, PKIMessage> wrapped) {
        return inbuf -> {
            try (final ASN1InputStream asn1InputStream =
                    new ASN1InputStream(inbuf)) {
                final PKIMessage msg =
                        PKIMessage.getInstance(asn1InputStream.readObject());
                if (LOGGER.isTraceEnabled()) {
                    // avoid unnecessary call of MessageDumper.dumpPkiMessage, if trace isn't enabled
                    LOGGER.trace("got " + MessageDumper.dumpPkiMessage(msg));
                } else if (LOGGER.isDebugEnabled()) {
                    // avoid unnecessary string processing, if debug isn't enabled
                    LOGGER.debug("got " + MessageDumper.msgAsShortString(msg));
                }
                if (msg == null) {
                    return null;
                }
                dumpMessage(msg, interfaceName);
                final PKIMessage ret = wrapped.apply(msg);
                if (LOGGER.isTraceEnabled()) {
                    LOGGER.trace("return " + MessageDumper.dumpPkiMessage(ret));
                } else if (LOGGER.isDebugEnabled()) {
                    // avoid unnecessary string processing, if debug isn't enabled
                    LOGGER.debug(
                            "return " + MessageDumper.msgAsShortString(ret));
                }
                dumpMessage(ret, interfaceName);
                checkNonce(interfaceName, msg, ret);
                return ret.getEncoded(ASN1Encoding.DER);
            } catch (final BaseCmpException ex) {
                throw ex;
            } catch (final Exception e) {
                throw new CmpProcessingException(interfaceName,
                        PKIFailureInfo.badDataFormat, e);
            }

        };
    }

    public static Function<InputStream, byte[]> adaptMsgHandlerToInputStreamToByteFunction(
            final String interfaceName,
            final Function<PKIMessage, PKIMessage> wrapped) {
        return instream -> {
            try (final ASN1InputStream asn1InputStream =
                    new ASN1InputStream(instream)) {
                final PKIMessage msg =
                        PKIMessage.getInstance(asn1InputStream.readObject());
                if (LOGGER.isTraceEnabled()) {
                    // avoid unnecessary string processing, if trace isn't enabled
                    LOGGER.trace("got from downstream "
                            + MessageDumper.dumpPkiMessage(msg));
                } else if (LOGGER.isDebugEnabled()) {
                    // avoid unnecessary string processing, if debug isn't enabled
                    LOGGER.debug("got from downstream "
                            + MessageDumper.msgAsShortString(msg));
                }
                if (msg == null) {
                    return null;
                }
                dumpMessage(msg, interfaceName);
                final PKIMessage ret = wrapped.apply(msg);
                if (LOGGER.isTraceEnabled()) {
                    // avoid unnecessary call of MessageDumper.dumpPkiMessage, if trace isn't enabled
                    LOGGER.trace("returning to downstream "
                            + MessageDumper.dumpPkiMessage(ret));
                } else if (LOGGER.isDebugEnabled()) {
                    // avoid unnecessary string processing, if debug isn't enabled
                    LOGGER.debug("returning to downstream "
                            + MessageDumper.msgAsShortString(ret));
                }
                dumpMessage(ret, interfaceName);
                checkNonce(interfaceName, msg, ret);
                return ret.getEncoded(ASN1Encoding.DER);
            } catch (final BaseCmpException ex) {
                throw ex;
            } catch (final Exception e) {
                throw new CmpProcessingException(interfaceName,
                        PKIFailureInfo.badDataFormat, e);
            }
        };
    }

    private static void checkNonce(final String interfaceName,
            final PKIMessage msg, final PKIMessage ret) {
        if (!Objects.equals(msg.getHeader().getSenderNonce(),
                ret.getHeader().getRecipNonce())) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badRecipientNonce,
                    "mismatch between sent senderNonce and received recipientNonce");
        }
    }

    private static void dumpMessage(final PKIMessage msg,
            final String interfaceName) {
        if (msgDumpDirectory == null || msg == null) {
            return;
        }
        final String subDirName = "trans_" + B64_ENCODER_WITHOUT_PADDING
                .encodeToString(msg.getHeader().getTransactionID().getOctets());
        final File subDir = new File(msgDumpDirectory, subDirName);
        if (!subDir.isDirectory()) {
            subDir.mkdirs();
        }
        final String fileprefix =
                interfaceName + "_" + MessageDumper.msgTypeAsString(msg);
        try (final FileOutputStream binOut =
                new FileOutputStream(new File(subDir, fileprefix + ".PKI"));
                final FileWriter txtOut =
                        new FileWriter(new File(subDir, fileprefix + ".txt"));
                final PemWriter pemOut = new PemWriter(new FileWriter(
                        new File(subDir, fileprefix + ".pem")))) {
            final byte[] encodedMessage = msg.getEncoded(ASN1Encoding.DER);
            binOut.write(encodedMessage);
            pemOut.writeObject(new PemObject("PKIXCMP", encodedMessage));
            txtOut.write(ASN1Dump.dumpAsString(msg, true));
        } catch (final IOException e) {
            LOGGER.error("error writing dump", e);
        }
    }

}
