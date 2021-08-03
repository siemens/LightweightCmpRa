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

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.anssi.ANSSIObjectIdentifiers;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.dvcs.DVCSObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.microsoft.MicrosoftObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.asn1.x509.sigi.SigIObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A utility class providing functions for dumping messages.
 */
public class MessageDumper {

    /**
     * OID Descriptor class
     */
    public static class OidDescription {
        private final String id;
        private final String declaringPackage;
        private final ASN1ObjectIdentifier oid;

        /**
         * Constructor for OID Descriptor class
         *
         * @param declaringPackage
         *            declaring package of the OID
         * @param id
         *            ID
         * @param oid
         *            ASN.1 representation of the OID
         */
        public OidDescription(final String declaringPackage, final String id,
                final ASN1ObjectIdentifier oid) {
            this.declaringPackage = declaringPackage;
            this.id = id;
            this.oid = oid;
        }

        /**
         * Get declaring package of the OID
         *
         * @return declaring package of the OID
         */
        public String getDeclaringPackage() {
            return declaringPackage;
        }

        /**
         * Get ID
         *
         * @return ID
         */
        public String getId() {
            return id;
        }

        /**
         * Get ASN.1 representation of the OID
         *
         * @return ASN.1 representation of the OID
         */
        public ASN1ObjectIdentifier getOid() {
            return oid;
        }

        @Override
        public String toString() {
            return declaringPackage + "." + id + " (" + oid + ")";
        }

    }

    private static final Logger LOGGER =
            LoggerFactory.getLogger(MessageDumper.class);

    private static final Map<Integer, String> TYPE_MAP =
            new ConcurrentHashMap<>();

    static {
        // load symbolic names defined in PKIBody
        for (final Field aktField : PKIBody.class.getFields()) {
            if (aktField.getType().equals(Integer.TYPE)
                    && (aktField.getModifiers() & Modifier.STATIC) != 0
                    && aktField.getName().startsWith("TYPE_")) {
                try {
                    TYPE_MAP.put(aktField.getInt(null),
                            aktField.getName().substring(5));
                } catch (IllegalArgumentException | IllegalAccessException e) {
                    LOGGER.error("error filling typemap", e);
                }
            }
        }
    }

    private static Map<String, OidDescription> keyToOidMap;

    private static Map<ASN1ObjectIdentifier, OidDescription> oidToKeyMap;

    private static void dump(final String indent, final ASN1Object object,
            final StringBuilder ret) {
        final List<String> nullMemberList = new ArrayList<>();
        for (final Method method : object.getClass().getMethods()) {
            if ((method.getModifiers() & Modifier.STATIC) != 0) {
                continue;
            }
            if (method.getParameterCount() != 0) {
                continue;
            }
            final Class<?> declaringClass = method.getDeclaringClass();
            if (declaringClass.equals(Object.class)
                    || declaringClass.equals(ASN1Object.class)) {
                continue;
            }
            final String methodName = method.getName();
            try {
                final boolean isGetter = methodName.startsWith("get");
                final boolean isArray = methodName.startsWith("to")
                        && methodName.endsWith("Array");
                if (!isGetter && !isArray) {
                    continue;
                }
                String memberName;
                if (isGetter) {
                    memberName = methodName.substring(3);
                } else {
                    memberName = methodName.substring(2).replace("Array", "");
                }
                final Object callRet = method.invoke(object);
                if (callRet == null) {
                    nullMemberList.add(memberName);
                    continue;
                }
                dumpSingleValue(indent + memberName, callRet, ret);
            } catch (final InvocationTargetException ex) {
                ret.append(indent + methodName + ": "
                        + ex.getTargetException().getMessage()
                        + ": <could not parse, skipped> ==============\n");
            } catch (final Exception ex) {
                ret.append(indent + methodName + ":" + ex.getMessage()
                        + ": <could not parse, skipped> ==============\n");
            }
        }
        if (!nullMemberList.isEmpty()) {
            ret.append(indent);
            ret.append('(');
            for (final String akt : nullMemberList) {
                ret.append(akt);
                ret.append('|');
            }
            ret.deleteCharAt(ret.length() - 1);
            ret.append("):<null>\n");
        }
    }

    /**
     * Dump an ASN1Object as string
     *
     * @param object
     *            the object to be dumped
     *
     * @return string representation of the object
     *
     */
    public static String dumpAsn1Object(final ASN1Object object) {
        if (object == null) {
            return "<null>";
        }
        final StringBuilder ret = new StringBuilder();
        try {
            dump("", object, ret);
        } catch (final Exception e) {
            LOGGER.error("dump error", e);
        }
        return ret.toString();
    }

    /**
     * Dump PKI message to a string.
     *
     * @param msg
     *            PKI message to be dumped
     *
     * @return string representation of the PKI message
     */
    /**
     * Dump PKI message to a string.
     *
     * @param msg
     *            PKI message to be dumped
     *
     * @return string representation of the PKI message
     */
    public static final String dumpPkiMessage(final PKIMessage msg) {
        if (msg == null) {
            return "<null>";
        }
        final StringBuilder ret = new StringBuilder(10000);
        ret.append("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ");
        ret.append(msgTypeAsString(msg));
        ret.append(" message:\n");
        try {
            dumpSingleValue("Header", msg.getHeader(), ret);
            dumpSingleValue("Body", msg.getBody(), ret);
            dumpSingleValue("Protection", msg.getProtection(), ret);
            dumpSingleValue("ExtraCerts", msg.getExtraCerts(), ret);
        } catch (final Exception e) {
            LOGGER.error("dump error", e);
        }
        ret.append("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
        return ret.toString();
    }

    private static void dumpSingleValue(final String indent,
            final Object callRet, final StringBuilder ret)
            throws ParseException {
        if (callRet == null) {
            ret.append(indent);
            ret.append(":<absent>\n");
            return;
        }
        if (callRet.getClass().isArray()) {
            if (callRet instanceof byte[]) {
                ret.append(indent);
                ret.append(": ");
                ret.append(Arrays.toString((byte[]) callRet));
                ret.append("\n");
                return;
            }
            final Object[] callRetArray = (Object[]) callRet;
            if (callRetArray.length == 0) {
                ret.append(indent);
                ret.append(":[]\n");
                return;
            }
            for (int i = 0; i < callRetArray.length; i++) {
                final Object elem = callRetArray[i];
                dumpSingleValue(indent + "[" + i + "]", elem, ret);
            }
            return;
        }
        if (callRet instanceof Iterable<?>) {
            final Iterable<?> callRetCollection = (Iterable<?>) callRet;
            int i = 0;
            for (final Object elem : callRetCollection) {
                dumpSingleValue(indent + "[" + i++ + "]", elem, ret);
            }
            return;
        }
        if (callRet instanceof ASN1GeneralizedTime) {
            ret.append(indent + ": " + ((ASN1GeneralizedTime) callRet).getDate()
                    + "\n");
            return;
        }
        if (callRet instanceof ASN1ObjectIdentifier) {
            ret.append(indent + ": "
                    + getOidDescriptionForOid((ASN1ObjectIdentifier) callRet)
                    + "\n");
            return;
        }
        if (callRet instanceof PKIFreeText) {
            final PKIFreeText val = (PKIFreeText) callRet;
            final int size = val.size();
            if (size == 0) {
                ret.append(indent);
                ret.append(":[]\n");
                return;
            }
            for (int i = 0; i < size; i++) {
                ret.append(
                        indent + "[" + i + "] : " + val.getStringAt(i) + "\n");
            }
            return;
        }
        if (callRet instanceof PollRepContent) {
            final PollRepContent val = (PollRepContent) callRet;
            final int size = val.size();
            if (size == 0) {
                ret.append(indent);
                ret.append(":[]\n");
                return;
            }
            for (int i = 0; i < size; i++) {
                dumpSingleValue(indent + "[" + i + "]/CertReqId: ",
                        val.getCertReqId(i), ret);
                dumpSingleValue(indent + "[" + i + "]/Reason: ",
                        val.getReason(i), ret);
                dumpSingleValue(indent + "[" + i + "]/CheckAfter: ",
                        val.getCheckAfter(i), ret);
            }
            return;
        }
        if (callRet instanceof Extensions) {
            final Extensions val = (Extensions) callRet;
            final ASN1ObjectIdentifier[] extensionOIDs = val.getExtensionOIDs();
            final int size = extensionOIDs.length;
            if (size == 0) {
                ret.append(indent);
                ret.append(":[]\n");
                return;
            }
            for (int i = 0; i < size; i++) {
                final Extension ext = val.getExtension(extensionOIDs[i]);
                dumpSingleValue(
                        indent + "[" + i + "]/Id"
                                + (ext.isCritical() ? "(critical)" : ""),
                        ext.getExtnId(), ret);
                dumpSingleValue(indent + "[" + i + "]/Value",
                        ext.getParsedValue(), ret);
            }
            return;

        }
        if (callRet instanceof ASN1Enumerated) {
            ret.append(indent + ": " + ((ASN1Enumerated) callRet).getValue()
                    + "\n");
            return;
        }
        if (callRet instanceof ASN1Primitive || callRet instanceof GeneralName
                || callRet instanceof Number || callRet instanceof CharSequence
                || callRet instanceof X500Name || callRet instanceof Date) {
            ret.append(indent + ": " + callRet + "\n");
            return;
        }
        if (callRet instanceof ASN1Object) {
            dump(indent + "/", (ASN1Object) callRet, ret);
            return;
        }
        ret.append(indent);
        ret.append(": <could not decode, skipped> ==============\n");
    }

    /**
     * Extract Relative Distinguished Names (RDNs) of a given type from a X500
     * Name
     * e.g. certificate subject.
     *
     * @param x500Name
     *            X.500 Name e.g. certificate subject.
     * @param rdnType
     *            RDN Type to be extracted e.g. CN
     *
     * @return RDNs of the requested type found in the X.500 name
     */
    public static final List<String> extractRdnAsStringArray(
            final X500Name x500Name, final ASN1ObjectIdentifier rdnType) {
        if (x500Name == null) {
            return null;
        }
        final List<String> ret = new ArrayList<>(1);
        for (final RDN aktRdn : x500Name.getRDNs(rdnType)) {
            for (final AttributeTypeAndValue aktTv : aktRdn
                    .getTypesAndValues()) {
                ret.add(String.valueOf(aktTv.getValue()));
            }
        }
        return ret;
    }

    /**
     * Get OID Description for a given OID (ASN.1 representation)
     *
     * @param oid
     *            OID (ASN.1 representation)
     *
     * @return OID Description for a given OID (ASN.1 representation)
     */
    public static OidDescription getOidDescriptionForOid(
            final ASN1ObjectIdentifier oid) {
        initNameOidMaps();
        final OidDescription ret = oidToKeyMap.get(oid);
        if (ret == null) {
            return new OidDescription("<unknown>", "<unknown>", oid);
        }
        return ret;
    }

    /**
     * // load ObjectIdentifiers defined somewhere in BouncyCastle
     */
    private synchronized static void initNameOidMaps() {
        if (keyToOidMap != null) {
            // already initialized
            return;
        }
        keyToOidMap = new TreeMap<>();
        oidToKeyMap = new HashMap<>();
        for (final Class<?> aktClass : Arrays.asList(CMPObjectIdentifiers.class,
                PKCSObjectIdentifiers.class, X509ObjectIdentifiers.class,
                OIWObjectIdentifiers.class, CRMFObjectIdentifiers.class,
                CryptoProObjectIdentifiers.class, EACObjectIdentifiers.class,
                NISTObjectIdentifiers.class, ICAOObjectIdentifiers.class,
                ISISMTTObjectIdentifiers.class, SECObjectIdentifiers.class,
                ANSSIObjectIdentifiers.class, BCObjectIdentifiers.class,
                BSIObjectIdentifiers.class, CMSObjectIdentifiers.class,
                DVCSObjectIdentifiers.class, GNUObjectIdentifiers.class,
                IANAObjectIdentifiers.class, ISISMTTObjectIdentifiers.class,
                ISOIECObjectIdentifiers.class, KISAObjectIdentifiers.class,
                MicrosoftObjectIdentifiers.class, MiscObjectIdentifiers.class,
                NTTObjectIdentifiers.class, OCSPObjectIdentifiers.class,
                TeleTrusTObjectIdentifiers.class, UAObjectIdentifiers.class,
                ETSIQCObjectIdentifiers.class, RFC3739QCObjectIdentifiers.class,
                SigIObjectIdentifiers.class, X9ObjectIdentifiers.class,
                PQCObjectIdentifiers.class,
                org.bouncycastle.asn1.x509.Extension.class)) {
            final String packageName =
                    aktClass.getSimpleName().replace("ObjectIdentifiers", "");
            for (final Field aktField : aktClass.getFields()) {
                if (aktField.getType().equals(ASN1ObjectIdentifier.class)
                        && (aktField.getModifiers() & Modifier.STATIC) != 0) {
                    try {
                        final ASN1ObjectIdentifier oid =
                                (ASN1ObjectIdentifier) aktField.get(null);
                        final String name = aktField.getName();
                        final OidDescription oidDescription =
                                new OidDescription(packageName, name, oid);
                        oidToKeyMap.put(oid, oidDescription);
                        keyToOidMap.put(nameAsKey(name), oidDescription);
                        keyToOidMap.put(nameAsKey(packageName + "." + name),
                                oidDescription);
                        keyToOidMap.put(nameAsKey(packageName + name),
                                oidDescription);
                    } catch (IllegalArgumentException
                            | IllegalAccessException e) {
                        LOGGER.error(
                                "error loading ObjectIdentifier Names from BC",
                                e);
                    }
                }
            }

        }
    }

    /**
     * Dumping PKI message to a string in a short form.
     *
     * @param msg
     *            PKI message to be dumped
     *
     * @return string short representation of the PKI message
     */
    public static String msgAsShortString(final PKIMessage msg) {
        if (msg == null) {
            return "<null>";
        }
        return msgTypeAsString(msg.getBody()) + " ["
                + msg.getHeader().getSender() + " => "
                + msg.getHeader().getRecipient() + "]";
    }

    /**
     * Get message type from a PKI message body as string
     *
     * @param msgType
     *            PKI message type
     *
     * @return message type as string
     */
    public static String msgTypeAsString(final int msgType) {
        return TYPE_MAP.get(msgType);
    }

    /**
     * Get message type from a PKI message body as string
     *
     * @param body
     *            PKI message body
     *
     * @return message type as string
     */
    public static String msgTypeAsString(final PKIBody body) {
        return TYPE_MAP.get(body.getType());
    }

    /**
     * Get message type from a PKI message as string
     *
     * @param msg
     *            PKI message
     *
     * @return message type as string
     */
    public static String msgTypeAsString(final PKIMessage msg) {
        if (msg == null) {
            return null;
        }
        return msgTypeAsString(msg.getBody());
    }

    private static String nameAsKey(final String name) {
        return name.toLowerCase(Locale.getDefault()).replaceAll("_", "");
    }

    public static String pkiStatus2String(final PKIStatusInfo status) {
        if (status == null) {
            return "<null>";
        }
        final StringBuilder statStringBuf = new StringBuilder();
        final PKIFreeText statusString = status.getStatusString();
        if (statusString != null) {
            final int size = statusString.size();
            if (size > 0) {
                statStringBuf.append('(');
                for (int i = 0; i < size; i++) {
                    statStringBuf.append(statusString.getStringAt(i));
                    statStringBuf.append(' ');
                }
                statStringBuf.append(')');
            }
        }
        switch (status.getStatus().intValue()) {
        case PKIStatus.GRANTED:
            return "GRANTED" + statStringBuf;
        case PKIStatus.GRANTED_WITH_MODS:
            return "GRANTED_WITH_MODS" + statStringBuf;
        case PKIStatus.REJECTION:
            return "REJECTION" + statStringBuf;
        case PKIStatus.WAITING:
            return "WAITING" + statStringBuf;
        case PKIStatus.REVOCATION_WARNING:
            return "REVOCATION_WARNING" + statStringBuf;
        case PKIStatus.REVOCATION_NOTIFICATION:
            return "REVOCATION_NOTIFICATION" + statStringBuf;
        case PKIStatus.KEY_UPDATE_WARNING:
            return "KEY_UPDATE_WARNING" + statStringBuf;
        default:
            return "<INVALID>" + statStringBuf;

        }
    }
}
