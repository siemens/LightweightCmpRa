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

import javax.xml.bind.annotation.adapters.XmlAdapter;

public class XmlPkiMessageTypeToIntAdapter extends XmlAdapter<String, Integer> {

    private final String[] TYPE_TABLE = {"ir", "ip", "cr", "cp", "p10cr",
            "popdecc", "popdecr", "kur", "kup", "krr", "krp", "rr", "rp", "ccr",
            "ccp", "ckuann", "cann", "rann", "crlann", "pkiconf", "nested",
            "genm", "genp", "error", "certConf", "pollReq", "pollRep"};

    @Override
    public String marshal(final Integer v) throws Exception {
        return TYPE_TABLE[v];
    }

    @Override
    public Integer unmarshal(final String v) throws Exception {
        for (int i = 0; i < TYPE_TABLE.length; i++) {
            if (TYPE_TABLE[i].equalsIgnoreCase(v)) {
                return i;
            }
        }
        return Integer.valueOf(v);
    }

}
